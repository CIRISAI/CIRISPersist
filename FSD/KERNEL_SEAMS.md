# Kernel seams: what persist hands a kernel, and what it keeps

Status: DESIGN, not built. Written 2026-11-12 at v61.3.0 (`f74d1b2a`) for the CC/constitution session's five
questions. No code changed and nothing was compiled.

Inputs read: persist `src/` at v61.3.0; CIRISConstitution tip `7b86bee` (`manifests/transitions.json`,
`reactions.json`, `family_model.json`, `governance_policy.json`, `formal/derivation/seat_duties.tsv`,
`duty_holders.tsv`, the `formal/` models); CEWP `crates/cewp-kernel` and `crates/cewp-sim`; CIRISHolon
(`OBJECT.md`, `DATA_OBJECT.md`, `FAST_AND_SLOW.md`, `FENCES.md`, `engine/CIRIS_HOLON_ENGINE.md`,
`engine/crates/holon/src/{merge,transport,sector,sharded,views}.rs`, `engine/crates/holon-closure`,
`lean/CIRISHolon/Object.lean`); `FSD/FINAL_REFACTOR.md` on the backlog worktree.

How claims are marked:

- **[T]**: tested, meaning I read the code or table at the anchor given.
- **[B]**: believed, meaning inferred, reported by someone else, or not run.

No count in this document comes from running a test. Counts marked [T] come from `grep`, `wc` or a short Python
read of a JSON manifest. Each one says how it was taken.

---

## 0. The answer

**Can one microkernel replace persist?** It can replace persist's **decisions**, but not persist. The kernel CC
describes takes an unsorted set of rows and returns views, a queue, effects and drafts. That is the right
contract for about 180 `check_*` gates and the folds behind them. It is the wrong contract for bytes at rest, the
canonical codec, signatures, KEM, the key store, replication, quotas, SQL paging and the effect executor. Those
are what persist would stay.

The premise does not hold for the code as built. Section 3 lists 20 places where persist's answer depends on the
order rows arrived in, on the receipt clock beyond first-held, or on state that is not rows. Most share one
cause: **the door refuses a row and drops it**, so what is held depends on what was held when the row arrived.
The fix is the one FINAL_REFACTOR §5.8 already named, "admit both, fold decides", applied to every door. The
kernel makes that fix complete because it has no way to drop a row. It can only return an inert verdict that
gives a reason.

Three of the breakers are in the rule text, not in persist: C557, the 8 `no …@admitted … else refuse` guard
clauses, and the W window that judges standing at receipt. The kernel cannot fix those. CC has to rule them
(§10).

§13 is the cost ledger: bytes and time per family, the acts that multiply rows, and the multi-row items that would
replace them.

Eric widened the scope: copying and placement ("how edge knows when to copy what where") are the same rules,
so they are kernel outputs too. `route(row, party)` answers hold / offer / serve / relay / park / discard from the
same tables (§5.9). Persist keeps storage and quotas; Edge keeps transport and the actual send.

The interface I propose (§5) is a pure `no_std + alloc` crate with no dependencies, built from CC's tables. Persist
calls it once per question. Every answer carries the row ids it read and the **dependency keys** it read, which
are its read set. Persist indexes those keys, and every row declares its write set from its own bytes alone. A new
row therefore invalidates only the answers whose read set meets its write set. That is the incremental-evaluation
contract, and it is also what removes the 61.3.0 per-row refold cost.

Performance is required, not hoped for. Eric's requirement is that the kernel "approach the theoretical limit for
performance for RUST/WASM and provably result in persist performing better post refactor". §11 sets out the
floor (crypto plus one write), the bound per rule cost class, and three gates that prove "better": an asymptotic
table, a differential gate on digest and time, and a WASM ratio gate. It also separates the store-side batching
that the kernel must not take credit for.

---

## 1. The kernel, restated, and one amendment

CC's definition, as confirmed by Eric:

| | |
|---|---|
| **in** | the unsorted set of signed, well-formed rows held; for each, the instant this node first held it; the reader's trust set; the node's own keys |
| **out** | views (what is true now, and why); the queue (transitions whose `from` matches the view and whose roles the standing meets); effects (stop serving, destroy bytes, wrap a key, raise a report); drafts (rows the node itself must sign); **routes**: for a row and a party (this node, a peer, a stranger), hold / offer / serve / relay / park / discard (§5.9, Eric's widening) |
| **replaces** | the store's decisions (`admission.rs` and the other gates) |
| **does not replace** | storage, sync, signature checking, indexes |
| **rules from** | `transitions.json`, `reactions.json`, `family_model.json`, `governance_policy.json`, `seat_duties.tsv`, `duty_holders.tsv` |

**Amendment: an irreversible act is acknowledged by a row.** Destruction is final (`formal/takedown` P4 [T]),
so a node that destroyed bytes holds a fact that no other row records. Under a later rule version a refold
could return "served" for bytes that are gone. CC's own vocabulary already contains the fix:
`reactions.json` `_meta.new_event_words` carries `purged` (7 uses) and `sealed` (4) [T]. **When persist
completes an irreversible effect, it signs a local-tier `purged` row naming the effect id.** That row re-enters
as input, the fold reads it, and the kernel's inputs stay rows plus the three non-rows. No separate effect log
is needed, and the gap between doing and signing is covered because every effect is idempotent by id (§5.6).

**The three non-rows, made precise.**

| non-row | type | why it is not a row |
|---|---|---|
| first-held instant | `Micros`, one per row, written once at the row's first insert and never rewritten | it is this node's receipt; replicating it would make it a claim |
| reader's trust set | the reader's key id plus the roots it accepts | the same rows read for two readers give two answers by design: `family_model.json` marks 32 fold cells `by=reader` [T, regex `by=(\w+)` over fold cells: reader 32, advisory 16, node 10, none 2] |
| the node's own keys | public key ids only: the node key and the identities it speaks for | it decides which drafts are this node's to sign and which `by=node` folds are "self". The kernel never sees a private key |

`at`, the evaluation instant, is the fourth input every call takes. It is the "now" against which windows that
open at a first-held instant are read. It is never compared to a signed instant inside a gate.

**Standing is a function of rows *and* first-held instants (W4 / C565, ruled by Eric).** Standing is judged at
the row's **signed** instant. That signed instant is trusted only when `first_held − asserted_at ≤ W`, and that
test is row-local: it reads one row and this node's first-held instant for it. **The node's clock decides only
what the node does**: when a window it opened closes, when an effect falls due, when to wake. It never decides
what a row means.

So standing is **not** a pure function of the rows alone. It is a function of the rows plus their first-held
instants, which are already a kernel input. The ruling leaves a residue, which CC's model pins and this document
records: a row first held within W on one node and past W on another **counts at the first and is inert at the
second**. Its `Inert` verdict names the cure: a current member's vouch for the past (CC 3.3.4, "A node does not
rebuild a group's past from old signatures… Events inside a vouched past are held on that vouch", `part_3`
around line 1568 [T]). That is a convergence of answers by a row that can be signed, not by a clock.

**Landed in CC rc19 at `8694fc1`** ("A verdict is read from the rows held, in whatever order they came") [T, read
the commit]:

- **CC 3.3.4 (standing).** A signer's standing is "judged at the event's signed instant, over the rows a node
  holds, and never at the instant the event reached the node", and the signed instant is trusted only where the
  node first held the event within W.
- **CC 4.5.13 (the lift window).** The window is "read on signed instants, the objection's against the act's",
  and an objection counts only where it was first held within W.
- **CC 4.5.3 (takedown).** A reversal or a lift voids the notice even when it arrives ahead of the notice. A node
  that already destroyed the bytes shows "not held here" and may fetch them again.

The model is `formal/kernel_world/KernelWorldSigned.tla`, with configs `KernelWorldSigned.cfg`, `_late.cfg` and
`_late_rest.cfg` [T, `ls`]. This closes the C565 mismatch noted earlier: both the standing reading and the lift
reading are ruled, and by the same rule.

---

## 2. Question 1: the seams

### 2.1 The line

| stays persist's | why | moves to the kernel |
|---|---|---|
| bytes at rest, blob/chunk storage, the at-rest cascade (`seal`/`open`/`wrap_dek_v2`) | it is the substrate | **when** to seal, wrap, rotate or destroy |
| canonical codec, JCS, `persist_row_hash`, wire index | a row's identity is its bytes | nothing; the kernel takes the `RowId` persist computed |
| hybrid signature verification (Ed25519 + ML-DSA-65), `tier_ingest.rs` [T, module doc 1-40] | it is a property of one row's bytes, and it is expensive | nothing; the kernel's precondition is "verified" |
| KEM (X25519 + ML-KEM-768) wraps and unwraps; the key store; key states (`Enabled → Disabled → Destroyed`, `community_dek.rs:1137-1170` [T]) | these hold secrets | which DEK goes to which recipient (a draft with a `WrapDek` hole, §5.7) |
| replication: set-difference pull, the held-record settle (`FSD/HELD_RECORD_SETTLE.md`), per-peer quotas (`replication/admission.rs` quota block [T]) | transport. A quota refusal is retryable and is not a verdict | nothing. **Constraint:** every transport refusal must be retryable, or the held set cannot converge |
| shape gates: envelope member shapes, column binding, hex digests, signed-instant form (`attestation_admit.rs:826-899` [T]) | functions of one row's bytes, i.e. "well-formed" | nothing; the kernel assumes well-formed. A family body grammar (CC `body` column) is the kernel's |
| SQL indexes, paging, `lifecycle_predicate` | a Rust fold cannot page (FINAL_REFACTOR §6.2) | the **rule** the predicate encodes. The SQL is generated from the kernel's table and witnessed against it (§6.2) |
| first-held stamping | it is the node's clock | nothing; it is an input |
| the effect executor (destroy, stop replication, deregister peer) | it has side effects | the effect list, its ids and when each is due |
| signing drafts, filling KEM holes | needs private keys | the draft (family, body, cause, deterministic id seed) |
| the local operational store (`sequence/` counters [T, `sequence/mod.rs:1-25`], tasks, telemetry, secrets) | FINAL_REFACTOR §8.2's fourth job; no federation verdict reads it | nothing |
| schema and migrations | storage | nothing, but a migration may never rewrite held rows again (§3, B19) |

### 2.2 Census: which decisions are already a function of the set held

"f(set)?" asks whether two nodes holding the same rows with the same first-held instants get the same answer
under every arrival order. Most gates are reached from `plan_put_attestation`
(`attestation_admit.rs:654`, about 57 gate calls between lines 694 and 1404 [T, grep of `::check_*`, `verify_*`,
`validate_*` in that range]). Other planes have their own doors (`*_admit.rs`).

| # | decision family | anchor | f(set)? | why | kernel form |
|---|---|---|---|---|---|
| 1 | hybrid signature at ingest | `attestation_admit.rs:1015` `verify_federation_tier_ingest` [T] | n/a | one row's bytes | stays persist (precondition) |
| 2 | shape and form | `attestation_admit.rs:826-899` [T] | yes | one row's bytes | stays persist (well-formed) |
| 3 | future-skew bound | `attestation_admit.rs:862` → `admission.rs:7420` `check_instant_binding` [T] | yes, if the refusal is retryable | compares the signed instant with receipt, which is first-held for an admitted row | kernel gate over (`asserted_at`, first-held). Persist keeps the drop because a re-offer converges [B] |
| 4 | family registered, reserved prefixes, private-use | `admission.rs:1669`, `:438`, `:711` [T] | yes for the registry part | registry lookup | `Kernel::classify` (the CC registry matcher) |
| 5 | signer seat by `identity_type` | `attestation_admit.rs:1284` → `admission.rs:19284` `check_reserved_prefix_admission` [T] | **no** | reads the attesting key's registration; a row that arrives before its key record is refused and dropped | standing fold: `seat_duties.tsv` role tokens; the verdict is inert until the key row is held |
| 6 | single node owner | `attestation_admit.rs:1244` → `admission.rs:13091` [T]; reader `owner_of` `admission.rs:12694` (two owners give `AmbiguousNodeOwner`) [T] | **no** | C557: the door refuses a second owner while one is live, so the outcome depends on whether the withdrawal arrived first (`formal/owner_binding` README [T]) | `owner_of` fold over live cosigned bindings; both bindings held; CC ruling needed (§10 W1) |
| 7 | delegation cycle | `attestation_admit.rs:1237` → `admission.rs:18517` (`received_at`) [T] | **no** | whichever edge closes the cycle on this node is refused; different nodes refuse different edges | fold: the cycle is a property of the held graph; its edges are inert by a tie-break (`min(asserted_at), min(id)`) |
| 8 | delegation term | `admission.rs:9803` [T] | yes | one row's envelope | kernel guard |
| 9 | `withdraws` authority and the stamp | `attestation_admit.rs:1163-1181`; `precedence.rs:258-280` `stamp_entitles` [T] | **no** | the rule number is stamped at the door only when the target is already held, and never rewritten. Persist's own doc: "an honest non-producer `withdraws` that arrived first retires nothing on this node until v62's fold derives entitlement" (`precedence.rs:263-266`) [T] | retraction entitlement computed by the fold at read time (CC `change` + `undo` columns); the stamp is deleted |
| 10 | structural-composer replay | `attestation_admit.rs:1105-1160` [T] | yes since #1157 | a distinct row naming the same target is admitted and "ranked at read time" (comment at `:1142`) | kernel `pick` (CC fold default) |
| 11 | cohort standing | `attestation_admit.rs:1062` → `admission.rs:2904` [T] | **no** [B] | reads the directory as held at receipt; refusal drops | standing fold, inert until the standing row is held |
| 12 | consent before scoring (`capacity:*`) | `attestation_admit.rs:1301` → `admission.rs:6332` (`received_at`) [T] | **no** | a capacity row that arrives before its `analyze` consent is dropped | guard `one consent:state:granted@admitted[…]` (CC already types it for `capacity:relay_delivery` [T]); inert until held |
| 13 | peer de-admission | `attestation_admit.rs:1383` → `admission.rs:14735` [T] | `by=node` | reads this node's own de-admissions | `by=node` fold; held, inert for this node |
| 14 | no moderator, no federate | `attestation_admit.rs:1396` → `admission.rs:17093` [T] | **no** | "refused if C has lost its last live moderate-holder" (comment `:1389-1391`), judged against what is held at receipt | view: room `locked` (`reactions.json` trust:{job} react, `read locked of group:roster` [T]) |
| 15 | attested subject is known | `attestation_admit.rs:1404` → `admission.rs:12895` [T] | **no** | missing-parent refusal; the order of arrival decides | inert, `Retry::WhenAny(Keys(subject))` |
| 16 | trust threshold on the key | `replication/admission.rs:133` `check_federation` [T] | **no** | the reader's trust score at receipt; refusal drops | `by=reader` view. Rows are held and the reader's view filters them |
| 17 | trust-root validity | `trust_root.rs:1407` `trust_root_valid` [T] | yes | a pure graph predicate over held rows and the reader's root ("never a client assertion, never a cached flag", module doc) [T] | kernel primitive (`by=reader`) |
| 18 | consensus protocol | `consensus.rs:213` `evaluate` [T] | yes | "Pure and total… a function of replicated, signed state only" (module doc) [T] | kernel primitive behind `governance_policy.json` |
| 19 | cosign hold | `cosign.rs` doc 1-70, `hold` `:853`, `execute_due` `:1199` [T] | **partly** | the quorum key is content-addressed and the union by signer is deterministic (yes). But only the primary's node mints the pending row, one open proposal per proposer is a partial UNIQUE (V214), and window expiry **drops** the pending and signature rows on a sweep (no) | the pending act is a view; cosignature rows stay held; expiry is a view (`lapsed`), not a deletion |
| 20 | self-roster W | `self_roster.rs:522-575` `check_roster_act_fresh` [T] | **no** | standing is judged "at receipt" (`is_roster_key_at(…, now)`); a row received before an eviction is admitted and one received after is refused, for good | §3 B5 |
| 21 | key-grant sealer W | `key_grant.rs:1197-1210` [T] | **no** | the same rule, with `Utc::now()` | §3 B5 |
| 22 | owner-binding affiliation W | `admission.rs:13032-13045` [T] | **no** | the same rule | §3 B5 |
| 23 | community DEK epoch | `community_dek.rs:545-575` `ensure_epoch_dek`; `store/sqlite.rs:9654-9684` `community_dek_bump_epoch` [T] | **no** | an `epoch = epoch + 1` counter row, bumped when `removed_at > minted_at`, where `minted_at` is local | epoch named by the digest of the departure rows (§3 B7) |
| 24 | takedown authority | `takedown_tombstone.rs:588-611` `content_binding` reads `Utc::now()` against `expires_at` [T] | **no** | the subject set is computed at receipt | fold at the notice's first-held instant |
| 25 | takedown destroy on receipt | `takedown_tombstone.rs:913`, `:981` (`purge_clock`) [T]; `Engine::purge_finalize` `engine.rs:9415` [T] | the state is (CC P5 [T]) | irreversible effect | `DestroyBytes` effect acknowledged by a `purged` row |
| 26 | peer record | `directory_admit.rs:155-176` "already exists with different pubkey" [T] | **no** | first writer wins (TOFU) | both records held; the view reads a conflict and serves neither |
| 27 | group head supersede | `group_supersede_admit.rs:77-100` `held_head_verdict` [T] | **no** | the head is replaced in place; a supersede that arrives before its predecessor is refused; of two forks, the first wins | the head is a fold over the chain (`prev_head_digest`); a fork is a view (`forked`) |
| 28 | accord proposal `created_at` | `accord_admit.rs:93-95` `monotonic_admission_instant(received_at, last)` [T] | **no** | a local instant allocated from the stored maximum and kept in the record | the order is the fold's (signed instant, then id); the cursor stays a serve position only |
| 29 | latest-wins upserts: occurrences, transport destinations, freshness floor | `store/sqlite.rs:25735`, `:25536-25538`, `:26695` (`WHERE excluded.asserted_at > …`) [T] | yes for value, **no** for the held set | `max` commutes, but the loser row is overwritten (not held), and a tie keeps the first | keep every row; the fold's `pick=max(asserted_at),min(id)` |
| 30 | location proof withdraw race | `evidence_admit.rs:199-200` "the first instant wins" [T] | **no** [B] | write race | fold |
| 31 | blob stream sequence | `blob_admit.rs:240-249` `SeqConflict` [T] | **no** | first append wins `seq` | stays persist **if** a stream is single-writer by its epoch binding [B]; otherwise a fold with a tie-break |
| 32 | persisted projections: trace, detection, hard_case, ledger, goal | `attestation_admit.rs:1411-1428` [T] | yes as caches | each is "the one function the rebuild calls too" (comments) [T] | rebuildable caches keyed by `RuleVersion` (§5.5) |
| 33 | node-emitted `hard_case` rows | `record_hard_case*` 20 call sites [T, grep, non-test files mixed with tests in `store/*`] | **no** | a fold result written as a row by the node that computed it | notice items of the view (FINAL_REFACTOR §5.6); only CC-listed signed acts stay rows (§10 W6) |
| 34 | `withdraws` admission depth | `attestation_admit.rs:1438-1441` (`dir.withdraws_delegation_depth()`, V157) [T] | **no** | an operator setting is written into the stored row and decides later | a governance-policy number, or removed (§10 W9) |
| 35 | clocked sweeps | `engine.rs:1794` evictions, `:2797` consent decay, `:6929` pending key grants, `:7314` community epochs, `:10000` self-roster due, `:10010` cosign due, `:9415` purge finalize [T] | the timing is per node by design | each reads `now` and acts | `reactions.json` clocks and expiries; the answer carries `valid_until` and persist wakes then (§5.4) |
| 36 | local-tier rows and promotion | `admission.rs:3246` `check_promotion_admission` [T] | `by=node` | local rows never replicate, so held sets differ by design | `by=node` partition |

**Totals.** Of 36 families, **7 are already set functions** (3, 4, 8, 10, 17, 18, 32). **3 belong to persist**
(1, 2, 31). **3 are `by=node` or `by=reader` by design** (13, 16, 36), although 16 also drops rows today. **2 are
effects or clocks the kernel schedules** (25, 35). **21 break the premise** (5-7, 9, 11, 12, 14, 15, 19-24, 26-30,
33, 34). Over the whole crate there are **180 distinct `pub fn check_*`** in `src/federation` outside the
invariant files [T, `grep -hoE 'pub (async )?fn check_[a-z_]+' | sort -u`]. I have not classified each one, so
the 21 are a floor [B].

---

## 3. Question 2: what breaks the unsorted-set premise

Each breaker gets an id, its class, an anchor and the computed verdict that replaces it. The classes are CC's
three plus the new ones found here:

- **(a)** refuse and drop
- **(b)** irreversible effect
- **(c)** receipt time beyond first-held
- **(d)** latest-wins overwrite
- **(e)** counter
- **(f)** persisted fold result
- **(g)** operator setting in a verdict
- **(h)** first writer wins
- **(i)** missing parent
- **(j)** migration rewrote held rows
- **(k)** breaker in the rule text
- **(l)** breaker in the reference kernel

| id | class | anchor | what goes wrong | computed form |
|---|---|---|---|---|
| B1 | a, k | owner binding: `admission.rs:13091` [T]; C557 | a new owner's binding that arrives ahead of the old owner's withdrawal is lost; two nodes read different owners (`formal/owner_binding` O6) | **RULED (C557, Eric; CC 3.2 at rc19 `8694fc1`): the fold decides.** Hold every binding; "no binding is refused and forgotten". Only bindings **this node's own key cosigned** count, **or the one the node's genesis record carries** (CC 3.2 "The first binding") [T]. If exactly one counts, it is the owner; any other count (zero, or two or more) is **unowned**; a binding the node did not cosign (a stranger's) is held and `Inert`. This is the model's `fold/unowned` reading, and it gives up O4. **Deltas from today:** `check_single_node_owner_admission`'s `NodeAlreadyOwned` refusal (`admission.rs:13129-13133`) [T] goes; `owner_of`'s `AmbiguousNodeOwner` error for two owners (`admission.rs:12702`) [T] becomes the verdict `unowned`, not an `Err`; and today a node's cosignature is demanded only after a reclaim (`check_post_reclaim_rebinding_admission`, `admission.rs:13140`) [T], whereas the ruling makes it the condition for **every** counted binding |
| B2 | a, f | `withdraws` stamp: `attestation_admit.rs:1163-1181`, `precedence.rs:258-280` [T] | entitlement depends on whether the target was held at the `withdraws`'s arrival | entitlement is a fold over (target, `withdraws`, the signer's standing at the `withdraws`'s signed instant); the stamp column is deleted. The release lead confirmed this independently (`attestation_admit.rs:1170-1181`, TESTED by them): the same rows in a different arrival order give a different retraction verdict, on the retraction path Edge reads. It is C557's class |
| B3 | a | delegation cycle `admission.rs:18517` [T] | the edge that closes a cycle depends on order | the cycle is a view; its closing edge is chosen by `max(asserted_at), max(id)` and is inert. Same on every node |
| B4 | a, i | gates 5, 11, 12, 14, 15 in §2.2 [T] | a row that arrives before its key record, consent, standing or subject is dropped; the peer may never re-offer it | **no gate drops.** The row is held with verdict `Inert { reason, retry: WhenAny(keys) }`. When a key in `retry` changes, its verdict is recomputed for free through the read-set index (§5.4). This is `formal/owner_binding`'s `again` reading applied to every door |
| B5 | c, a, k | W at receipt: `self_roster.rs:556-575`, `key_grant.rs:1197-1210`, `admission.rs:13032`, `admission.rs:5301` [T] | "a signer stands at its signed instant; past W it must also stand **at receipt**." Standing at receipt is the held set at receipt, so an eviction that arrives after the row admits it on one node and refuses it on another, for good | **RULED (W4 / C565, Eric; CC 3.3.4 at rc19 `8694fc1`):** judge standing at the row's **signed** instant over all rows held, ordering the eviction by its own signed instant. Trust that instant only when `first_held − asserted_at ≤ W` (row-local). The four `now` reads go (`self_roster.rs:567`, `key_grant.rs:1197`, `admission.rs:13032`, `:5301`). **Residue (pinned by CC's model, accepted):** a row first held within W on one node and past W on another counts on the first and is `Inert { reason: asserted_at_stale, missing: vouch }` on the second. The cure is a current member's vouched past (CC 3.3.4), which is a row, so the two nodes converge once it is held (§1) |
| B6 | a, c, e | cosign hold: `cosign.rs:853`, `:1199`, V214 partial UNIQUE [T, doc] | expiry deletes held rows on a sweep; one open proposal per proposer refuses the second | pending, assembled and lapsed are views over held `cosign:*` rows; the reaction `drop_held` (`reactions.json` [T]) becomes the view `lapsed` plus an optional storage reap (§3.1) |
| B7 | e, c | community DEK epoch: `store/sqlite.rs:9654-9684`, `community_dek.rs:557-575` [T] | a mutable counter; it rotates when a signed `removed_at` exceeds a **local** `minted_at`; bumping twice for one removal gives two epochs [B] | epoch identity = `H(community, minter, the departure rows since the previous epoch)`. Rotation is due when the held departure set grows (`formal/key_plane` K6: "the epoch changes only after a departure or a rotation falling due" [T]). The minted DEK is still persist's secret |
| B8 | c | takedown `content_binding` `takedown_tombstone.rs:602-611` [T] | the subject set is read against `Utc::now()` | read at the notice's first-held instant |
| B9 | b | destroy bytes and destroy keys: `takedown_tombstone.rs:913`, `engine.rs:9415`, `community_dek.rs:1160-1170` [T] | final; under a later rule version the view could say "served" | `Effect` with a deterministic id, acknowledged by a local `purged` row (§1). Under a new rule version a refold that would not have destroyed raises `Notice::EffectNoLongerJustified`, never an undo |
| B10 | d | latest-wins upserts `store/sqlite.rs:25536`, `:25735`, `:26695` [T] | the loser row is gone; a tie keeps the first | hold every row; `pick=max(asserted_at), min(id)` |
| B11 | h | peer record TOFU `directory_admit.rs:155-176` [T] | the first pubkey for a key id wins | hold both; the view reads `conflict` and serves neither (the same law as O8, "a reader that holds two reads none") |
| B12 | h, a | group head supersede `group_supersede_admit.rs:77-100` [T] | a successor that arrives early is refused; of two forks, the first wins | a fold over the `prev_head_digest` chain; a fork is a view; the head is `pick` over the unforked tip |
| B13 | c, e | accord `created_at` `accord_admit.rs:93-95` [T] | a local instant enters the record | the serve cursor stays persist's and no verdict reads it [B: confirm no fold reads `created_at`] |
| B14 | f | `hard_case` emissions, 20 call sites [T] | a node writes its own fold result as a signed row; peers replicate this node's opinion | **DERIVED (W6):** what every node can read from rows plus its clock is a **notice**, not a row. A signed row remains only where someone outside the node must be told or held to it: key grants, `consent:state:expired`, `consent:decay:*`, the safeguarding escalation of CC 3.4.13, and the takedown/purge tombstone. CC will type all fifteen `hard_case` kinds |
| B15 | g | `withdraws_depth` per row `attestation_admit.rs:1438-1441` [T] | the operator's depth is frozen into the row and later folds read it | the depth comes from governance policy (one number for all) or the column goes |
| B16 | c | the 4 folds that read `received_at` today, named in persist's own doc (`attestation_admit.rs:76-82`, pinned by `store/parity.rs:3444` `PLAN_INSTANTS`) [T] | folds judged at receipt | judged at `fold_at` (signed instant); `received_at` only in row-local bounds |
| B17 | a, c | trust threshold at the door `replication/admission.rs:133` [T] | the reader's trust at receipt decides what is held | hold; a `by=reader` view filters. **The cost:** more rows held from low-trust keys, so quotas and placement carry the load (§12 R1) |
| B18 | k | 8 guard clauses `no X@admitted[…] else refuse` in 5 families (`census:composite:{class}`, `census:member:share`, `census:share:{class}`, `membership:{stage}`, `retirement:{state}`) [T, regex over `transitions.json` guard cells] | uniqueness by refusal keeps whichever arrived first, which is C557's shape again inside the CC tables | each needs a `tie_break` (CC#203's column) so the duplicate is held and inert by `min(asserted_at), min(id)` (§10 W2) |
| B19 | j | migrations that delete or rewrite held rows: 22 sqlite migrations carry `UPDATE` or `DELETE` [T, grep]; e.g. V196 deletes `federation_attestations` rows; V192 resets emission flags so wraps re-emit [T] | the held set changed with no row saying so | a schema change may add columns and indexes. A held-set change is a signed row (`purged`) or a rule-version change the kernel recomputes from (§5.8) |
| B20 | l | cewp-kernel `door` commits only on `Ok` (`processor.rs:1078-1084`); `step` returns `Refusal::FamilyMismatch` when an object id was first claimed under another family, and `fold` takes object families in `asserted_at, id` order (`processor.rs:80-87`, `:955-972`) [T] | the reference kernel drops as well, and a signer-chosen backdated instant claims an object id | the converged kernel never drops (§7) |

**Not breakers, checked:**

- The composer replay (#10) is order-free since #1157 [T].
- Signed-instant ordering inside a fold is allowed by FINAL_REFACTOR §5.8 ("a fold may order by signed
  instants"), and the cewp-kernel's windows run from first-held (`processor.rs:197`, `:308`, `:564`) [T].
- The sequence counter is local and operational [T].

### 3.1 Storage still shrinks

"Admit both" does not mean "keep everything". Purge, reap, eviction and erasure shrink the held set **outside**
the kernel (FINAL_REFACTOR §5.8 already says so). The rule that keeps this sound: a reap may remove only a row
whose removal changes no verdict the kernel would compute. The kernel answers that directly:
`Kernel::removable(row) -> Removable`. This is Holon's light-cone removal (`sector.rs` §2-3 [T]): a row outside
every live verdict's read set is provably removable. A row inside one is removable only by an acknowledged
effect.

---

## 4. Holon: what transfers

Eric pointed at the "core crates for the quantum stuff". The transferable ideas are mechanisms, not physics. CC
named three of them, and this table adds the four the code shows.

| idea | where in Holon | persist form |
|---|---|---|
| **One merge law** | `engine/crates/holon/src/merge.rs` [T]: "Ledgers fold associatively and commutatively, so ANY sharding, ordering, or distribution of a fold is deterministic without coordination… a LAW WITH TESTS" | every family fold's per-object state is a `Join` (a semilattice: associative, commutative, **idempotent**, the last because rows are re-delivered). CC's default fold (`pick=rank(recants>withdraws>supersedes),max(asserted_at),min(attestation_id)`, `family_model.json` `_meta.fold.default` [T]) is already a join. Each family ships the law test by struct equality, as `merge.rs` does for its exact rings |
| **A view is admitted only when its square commutes** | `lean/CIRISHolon/Object.lean` (`Closed v T`), `holon-closure/src/lib.rs` [T] | an incremental path is a view. It is admitted only if `fold(S ∪ {r}) == apply(fold(S), r)` over generated sets. A projection or cache without that certificate is not used for a verdict |
| **Failure as a witness pair** | `nonfactoring_iff_not_closed`; `OBJECT.md` "every bug report against a tier should ship one" [T] | the divergence report (§6.3) is two held sets, or two orders of one set, that the view cannot tell apart and that the kernel or door splits |
| **Backward light cone = read set** | `holon/src/sector.rs` §2: a gate outside the observable's cone "is REMOVABLE, provably"; a gate inside enlarges the cone [T] | `Answer.reads` is the cone; `touches(row)` is the row's support. Invalidate exactly where they meet; reap rows outside every cone (§3.1) |
| **Shards with disjoint columns run in any order; a crossing is counted** | `holon/src/sharded.rs` doc: a write-only XOR accumulator merged "in shard order… the schedule is not an input"; cross-boundary CX is "REPORTED per run and never assumed" [T] | partition by `DepKey`. Families whose read sets are disjoint evaluate in parallel. A cross-partition read (standing, read by many families) is the "CX" and is counted per evaluation |
| **The certificate never rides a transport** | `holon/src/transport.rs`: `Transported { cert: None }` unless a `CertWitness` is supplied [T] | a peer's verdict never arrives with its rows. The receiving node recomputes. This is "a fold result is served, never written" as a type: `Answer<T>` is not `Serialize` into a row |
| **Unserved is not zero** | `holon-closure` `LedgerRow::read` returns `None` for an unserved channel [T] | a transition whose cell is `gap` or `Prose` is `Verdict::Unserved { cell }`, never "refused" and never "admitted". The CC worklist (§10) is the list of unserved cells |
| Refusal names the gate that would lift it | `FENCES.md` law: "refuses, naming the gate whose passing would lift the refusal"; an allowlist entry needs an owner and an exit [T] | `Inert { missing, retry }`. Every bespoke gate that survives the move needs an owner and an exit (a CC cell id), or it is suppression |
| Derive the zeros first | `FAST_AND_SLOW.md` §2 "Negation": test whether a stake is a theorem's constant before running it [T] | before a differential, mark families whose verdict is constant (no lifecycle, any-key, unenforced): FINAL_REFACTOR counts 86 + 37 of them [B]. They need one vector each, not a corpus |

### 4.1 CC's short list, checked

CC sent a short list of Holon mechanisms, and I verified each cite before relying on it. Holon's discipline in one
line: anything that could depend on order is a fold over a commutative monoid of exact, integer-backed values.
That is proved three ways: by law tests, by planted mutations that must fire, and by an exact digest.

Two notes on where things live. `INTERFACE.md` is empty (0 bytes [T]); the interface is in the crate headers.
`FENCES.md` lists refused capabilities; the dependency fences are in `engine/ci-gates.sh` and the
`engine/Cargo.toml` comments.

| # | mechanism | cite (checked) | kernel form |
|---|---|---|---|
| 1 | **One merge law as a trait** | `MergeLedger { empty, merge }` and `fold` (`holon/src/merge.rs:15-18`, `:62-64`) [T]. One generic law test compares a forward fold with a reversed one, then checks identity (`holon/tests/laws.rs:11-20`) [T]. In Lean a run is a `Multiset`, so "two schedules of the same work are the same multiset" (`lean/CIRISHolon/MergeLaw.lean:14-16`), and `shardedFold_invariant` is at `:62` [T]. "This replaces ACID wholesale" (`DATA_OBJECT.md:168-174`) [T] | the kernel's input is a multiset of rows. Every accumulation (count, roster, holder set, latest-wins pick) is a `MergeLedger` instance. **This is the census's test:** a rule that cannot be written as one is an order-dependent door. Every B-row in §3 fails it, and that is the reason it is a breaker |
| 2 | **Order-independent bytes** | `mesh::canonicalize` (`holon/src/mesh.rs:111`) [T]. The test at `holon/tests/mesh.rs:440-466` asserts that the forward and reversed folds are **not** struct-equal, that they are value-equal, and that canonicalised they are equal. Its message says to retire the test once the ledger grows a canonical form [T] | kernel outputs are canonicalised before they are compared or hashed. Sets are sorted by `RowId`; maps are `BTreeMap`. A test pins every place where canonicalisation is still load-bearing |
| 3 | **Integers only; refuse on overflow** | `holon-scene/src/lib.rs:19-20`: "Integers only. No float appears in this crate, so a native build and a wasm build agree bit for bit by construction" [T]. `holon/src/ledger.rs:11-17`: the ring "REFUSES (panics) on overflow rather than wrapping" [T] | scores, weights and thresholds are exact: integer fixed-point or a rational `(num, den)` in `u64`/`i128`, using checked arithmetic. Overflow is a **verdict** (`Unserved { cell }` with an overflow reason), never a panic and never a wrap, because a kernel must not abort a node. This is also CC's open COSE float gap (§10 W16). Persist carries floats into verdicts today. `Attestation.weight` is `Option<f64>` (`types.rs:1645`) [T], and the weighted-rubric arm of `consensus::evaluate` sums `f64` weights (`consensus.rs:38`, `:418`, `:436`) [T]. An `f64` sum is order-dependent past exactness, which is Holon's `RentLedger` warning (§4). **DERIVED at CC rc19 `6453665`** ("A group's protocol is a closed list of counts"): `weighted:{rubric}` **stays**, but every weight and the threshold are **whole numbers** on the group's signed record (CC 3.3.4). So the arm keeps its meaning and loses its floats (`u64` weights, a `u64` threshold, compared exactly). `custom:` is removed (§5.3a) |
| 4 | **An exact digest as the certificate** | `Digest([u64; 4])`, merged by lane-wise `wrapping_add` (`holon-tables/src/digest.rs:39-64`) [T]. `digest_commutes` (`MergeLaw.lean:77`) and `digest_convicts` (`:88`) [T] | `Answer` carries a `Digest`: each output element is hashed with its stable id into four lanes, and the lanes are summed. The sum is order-free by construction. Two nodes compare one digest of their views; the differential compares digests per fixture |
| 5 | **The permutation is a test input** | `p2_a_scrambled_fold_order_changes_nothing` runs two scrambles and asserts that each **is a permutation** and **is not the identity** ("P2 plant is vacuous", `holon/tests/mesh_clifford_plants.rs:519-543`) [T] | every kernel vector runs under N shuffles of its row multiset, and the harness asserts that each shuffle differs from the identity (§6.2) |
| 6 | **Rights and unknowns as types** | `Transported { value, cert: None }` unless a `CertWitness` is supplied (`holon/src/transport.rs:15-48`) [T]. Unserved is `Option`, never 0 (`holon-closure/src/lib.rs:28-34`) [T] | a `Standing` value can be constructed only with its granting chain (`Standing { roles, chain: SmallVec<RowId> }`, private constructor). A row that is not held is `Unknown`, never `false`. `Answer<T>` has no path into a stored row |
| 7 | **Four-valued verdicts and named refusals** | `Verdict { Pass, Fail, Branch(char), Void }`; Void is sticky ("a later passing leg cannot lift it"); `admits()` is true only for Pass and Branch (`holon-campaign/src/gate.rs:20-57`, `:127-140`) [T]. `route()` returns `Err(String)` naming why a circuit leaves a tier (`holon-qasm/src/lib.rs:281-330`) [T] | the kernel's `Verdict` maps one to one: `Live` = Pass; `Inert` = Fail, carrying its reason token **and the row that would cure it**, which is the queue item; `Branch` = a policy outcome chosen from a pre-committed set (enacted, cancelled, or lapsed under two_path); `Unserved` = Void. Nothing to evaluate is Void, never admitted, and a Void verdict on a row stays Void under that rule version |
| 8 | **Mutations built in; a fenced build** | `enum Mutation` with a must-not-move control (`ReverseRegionOrder`) and must-move or must-convict defects (`holon-tables/src/mutation.rs:25-`; the doctrine is at `holon-tables/src/lib.rs:66-89`) [T]. A dependency **allow-list** gate ("fails on ANY new name") at `engine/ci-gates.sh:18-33`, and a WASM gate that **fails** when `node` is missing rather than skipping (`:852-894`) [T]. The allow-list gate covers `ciris-sim-core` [T]; I did not check where the referee is declared as a dev-dependency [B] | the kernel ships `enum KernelMutation` (e.g. `DropOnRefuse`, `LastProcessedWarmStart`, `StampAtDoor` must convict; `ReverseInput`, `ShardFolds` must not move). It ships an allow-listed dependency set (empty, or a single vendored sha256), a `no_std` build gate, and a WASM run gate that fails without its runner |

**The lesson from `holon-tables/src/lib.rs:30-48` [T].** "The obvious design is for a worker to start from
whatever it solved last. That design is WRONG": the answer becomes a function of how the work was scheduled.
Two rules follow for the kernel. **Join by stable id, never by array index.** **Never carry state from "what I
processed last".** That is the general form of C557 and of B2: a door that consults "what I happened to hold
when this arrived" is a worker warm-starting from its last solve. An incremental or warm path must be a
canonical function of the set, with first-held instants as explicit inputs.

### 4.2 The frame: a view is admitted when its square commutes

`Closed v T := ∃ h, v ∘ T = h ∘ v` (`lean/CIRISHolon/Object.lean:59`) [T]. A failure has a normal form,
`nonfactoring_iff_not_closed` (`:91`) [T], and `holon-lattice/src/probe.rs:103` exhibits one as a `Witness`
struct ("an exhibited pair of micro-states agreeing under the chart and disagreeing after the motion") [T].

For persist:

- `T` is "a row arrives", and `v` is the kernel's view.
- Persist's index or answer cache is admissible **exactly when** updating it on arrival gives the same view as
  refolding the set. That is `h`.
- A divergence report **is** a witness pair: two row sets, or two orders of one set, with the same index state
  and different verdicts after one arrival.

§5.4 (incremental evaluation) and §6.3 (divergence reports) are organised on this frame.

### 4.3 A worked example of the merge law: ranked choice (CC 4.5.13, rc19)

Eric: "make sure we support ranked choice voting natively". CC 4.5.13 defines ranked choice once, for any choice
among options, and its definition **is** the merge law [T, read at rc19]:

- **SUMMARY**: a count per ranking. It is a commutative monoid that merges by adding, kept up to date per ballot:
  `Summary = BTreeMap<RankingId, u64>`, `merge(a, b)` adds per key, and `empty` is the empty map. At most
  `k + k(k−1) + k(k−1)(k−2)` cells for 3 ranks. CC: "The tally is a sum, so it is the same in whatever order the
  ballots arrived, and two tallies of separate parts add to the tally of the whole."
- **One ballot per person, `pick=agree`**: "a person whose ballots disagree has none". This is the one
  non-monotone step, and it sits **before** the sum. Each person's ballots fold to `Agree(ranking) | None`, and
  the summary adds the resolved value. Because counts are integers (an abelian group, not just a monoid), a
  person's second ballot updates the summary in O(1): subtract their old resolved value, add the new one. The
  standing set "at the count" (`moderator_election`: "member, one voice a person, the set at the count") is an
  invalidation edge on `Roster(group)`: a member's removal subtracts their contribution.
- **FINISH**: instant runoff over the summary alone, in whole numbers, in fewer rounds than there are options. A
  tie for weakest goes against the option later in the declared order.

So ranked choice is native in the kernel's sense: one `MergeLedger` instance (§4.1 #1), keyed by stable ranking
id (never by option index), with a pure finish. The law test is the same as `holon/tests/laws.rs`: forward and
shuffled folds of the resolved ballots give equal summaries by struct equality.

**Today:**

- Persist has **no** ranked door. `ballot:moderator` is "registered and not gated", and `governance_policy.rs:555-563`
  reads `moderator_election` as "a `ranked` row persist has no door for" [T].
- cewp-kernel's `irv` (`processor.rs:20-78`) differs from CC 4.5.13 in three places [T]:
  - it keeps the **last-inserted** ballot per signer (`seen.insert`), which is order-dependent, where CC says
    disagreeing ballots count as none;
  - it breaks a tie for weakest by **lexicographic id** (`losers.sort()`), where CC says against the later option in
    the declared order;
  - it refolds the ballots every round, where CC finishes from the summary.

  §7's convergence fixes all three.

What does **not** transfer: the f64 tiers, conditioning, rent decay as physics, and MPS truncation. Every kernel
verdict is integer arithmetic over signed inputs (FINAL_REFACTOR §5.3). `RentLedger`'s tolerance law
(`merge.rs` [T]) is the warning: a fold that needs a tolerance is not order-free, and the kernel does not have
one.

---

## 5. Question 3: the interface

### 5.1 Shape

```text
            persist                                            kernel (pure, no_std+alloc, 0 deps)
 ┌──────────────────────────────┐   classify(raw) ───────▶  FamilyKey | Malformed
 │ codec ─ verify ─ first_held  │   touches(row)  ───────▶  KeySet               (row alone)
 │   │                          │   step(src,row,ctx) ───▶  Answer<Verdict>      (door + preview)
 │   ▼                          │   view(src,q,ctx) ─────▶  Answer<View>
 │ held store + indexes ◀─ src ─┼── queue(src,who,ctx) ──▶  Answer<Vec<QueueItem>>
 │ answer cache (reads → keys)  │   react(src,keys,ctx) ─▶  Reactions{effects,drafts,notices,wake}
 │ effect executor, signer, KEM │   removable(src,row) ──▶  Removable
 └──────────────────────────────┘
```

The kernel never calls a backend, never reads a clock and never sees a secret. `src` is a read-only callback
that persist answers from its indexes.

### 5.2 Rows in

```rust
/// Persist computes it (persist_row_hash today); the kernel never hashes row bytes.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RowId(pub [u8; 32]);
pub type Micros = i64;                         // µs since the epoch: the substrate resolution

/// The one typed view of a verified, well-formed row (FINAL_REFACTOR §4.1 is its producer).
pub struct RowView<'a> {
    pub id: RowId,
    pub family: FamilyKey,                     // from Kernel::classify, stored by persist as an index column
    pub verb: Verb,                            // attest | withdraw | recant | supersede | voice …
    pub signer: KeyId<'a>,
    pub cosigners: &'a [KeyId<'a>],            // verified co-signatures (cosign rows stay rows)
    pub object: ObjId<'a>,
    pub subjects: &'a [KeyId<'a>],
    pub scope: Scope<'a>,                      // tier + group
    pub refs: &'a [RowId],                     // references_attestation_id, prev_head, …
    pub asserted_at: Micros,                   // signed: folds may ORDER by it; gates never compare it to `at`
    pub expires_at: Option<Micros>,            // signed
    pub members: &'a dyn Members,              // the body slots guards and folds name (val:*, leaf:*)
}

pub struct Held<'a> { pub row: RowView<'a>, pub first_held: Micros }
```

### 5.3 Context, answers, verdicts

```rust
pub struct Ctx<'a> {
    pub at: Micros,                  // the evaluation instant (persist's clock, once per call)
    pub reader: &'a TrustSet<'a>,    // by=reader folds
    pub me: &'a SelfKeys<'a>,        // by=node folds; whose drafts are ours
}

/// Every answer says what it read (CC view.cddl provenance.rows / provenance.rule).
pub struct Answer<T> {
    pub value: T,
    pub rows: SmallVec<RowId>,       // the rows the value rests on, for a client's "why"
    pub reads: KeySet,               // the dependency keys it read: the light cone
    pub rule: RuleRef,               // RuleVersion + cell ids (transition / guard / fold / reaction)
    pub valid_until: Option<Micros>, // the next clock edge (window close, expiry); None = only rows change it
    pub digest: Digest,              // [u64; 4], lane-wise wrapping_add of H(stable id ‖ canonical value) per element (§4.1 #4)
}

/// Every number a verdict reads is exact. No f32/f64 type exists in the crate (a lint and a grep gate).
pub struct Ratio { pub num: u64, pub den: u64 }   // thresholds, weights; compared by cross-multiplying in u128

pub enum Verdict {
    /// The transition this row makes, and the object state after it.
    Live { transition: TransitionRef, to: State },
    /// Held, but makes no move. A computed verdict, never a rejected write.
    Inert { reason: Token, missing: Missing, retry: Retry },
    /// No typed rule decides this: a CC gap/prose cell. Not refused, not admitted.
    Unserved { cell: CellRef },
}
pub enum Retry { Never, WhenAny { keys: KeySet, lapse: Micros }, At(Micros) }
// No halting edges (CC, under Eric's delegation): an Inert that waits for a row MUST carry a lapse. There is no
// wait without a deadline. On lapse persist drops its local copy (a storage act, not a verdict), and the row stays
// re-offerable. Deadlines per origin are §5.9a.
// Holon's four values (§4.1 #7): Live = Pass, Inert = Fail (with the curing row), a policy Branch rides in
// Live.to (enacted | cancelled | lapsed), Unserved = Void. Overflow in any count is Unserved, never a wrap.
pub struct Missing { pub roles: SmallVec<Role>, pub voices: Option<(u32, u32)>, pub rows: SmallVec<Need> }
```

`Token` is the public refusal contract (FINAL_REFACTOR §5.6). Today's tokens are kept byte for byte, so
`federation_*` kinds and Python types do not move in a mechanical step. `Retry::Never` is terminal and the rest
are retryable, which is what Edge's retry schedule reads.

### 5.3a The protocol vocabulary is closed (DERIVED, CC rc19 `6453665`)

Eric delegated four open questions to CC under two goals: "1) fold the rows and end up with the same conclusion
2) do so efficiently and without any halting edges". On group protocols CC derived:

- **`custom:` is removed.** A declaration of it is refused outright, as malformed at the codec, not held inert. Today
  persist evaluates `custom:{id}` from `policy_blob.custom`, nested up to `MAX_CUSTOM_DEPTH` = 8
  (`consensus.rs:41`, `:317-324`) [T]. That arm, its depth limit and its tests go.
- **`weighted:{rubric}` stays**, with whole-number weights and threshold on the signed group record (CC 3.3.4).
  This closes W16 for protocols.
- **An operator `cohort_subkind` is a label with no predicate** (CC 4.4.3.2.3). The kernel never branches on it.
- **A growing quorum is `majority`.**
- **The list is closed:** five canonical protocols plus `open:self_admit`. The kernel's `Rule` is then a closed
  enum with no `Prose` arm for protocols. That removes cewp-kernel's `Rule::Prose` path for this column (§7).

**What a refusal looks like.** The only write that is refused outright is one persist refuses before the kernel:
malformed, unverifiable, over quota, or not placeable (§5.9). Everything else is held and gets a `Verdict`:

| caller | `Live` | `Inert` | `Unserved` |
|---|---|---|---|
| local author, before signing (preview) | sign and store | return the token; nothing is signed (the preview is the refusal the signer sees) | return `unserved`; nothing is signed |
| local author, signed row | store | store, return the token (`kind` unchanged) | store, return `unserved` |
| replicated row | store | store, count `persist_inert_total{token}` | store, count |

Persist keeps the right **not to sign** an inert act of its own. It loses the right to drop someone else's.

### 5.4 Incremental evaluation: read sets and write sets

```rust
/// The partition keys. A fold reads by key; a row writes by key.
pub enum DepKey {
    Object(ObjHash),                       // one object's lifecycle
    Refs(RowId),                           // rows that cite a row
    Roster(GroupHash),                     // a group's membership and protocol
    Standing(KeyHash),                     // a person's roles
    Keys(IdentityHash),                    // an identity's key roster and occurrences
    Slot { family: FamilyKey, slot: SlotId, value: ValueHash }, // guard selectors: one X@admitted[a=b]
    Content(Digest),                       // a blob's binding and holding set
}

impl Kernel {
    /// The keys a row can change. A function of the row ALONE, so persist can
    /// index a row before evaluating anything.
    pub fn touches(&self, row: &RowView) -> KeySet;
}

pub trait HeldSource {
    /// Every held row under `key`. Persist answers from an index on exactly these keys.
    fn rows(&self, key: &DepKey, f: &mut dyn FnMut(Held<'_>)) -> Result<(), SourceError>;
}
```

The persist side keeps one table and one index:

```text
kernel_answers(question_key, rule_version, value_blob, rows, valid_until)
kernel_answer_reads(dep_key, question_key)          -- the inverted cone
```

On a new row `r`, persist computes `K = touches(r)`, deletes every answer whose reads meet `K`, and recomputes
on demand or eagerly for the questions the host subscribes to. A sweep wakes at `min(valid_until)`. That is the
whole invalidation protocol. It replaces the seven clocked sweeps in §2.2 #35 with one wake.

The cache is a **projection**: rebuildable, dropped wholesale when `rule_version` changes, and never the source
of a verdict. It is admitted only under the commuting square: the differential in §6.2 includes
`cached(S, r) == fresh(S ∪ {r})`. A failure is a witness pair, and that family falls back to "no cache".

**The admissibility condition, stated as the square.** Let `v(S)` be the kernel's answers over held set `S`, let
`T_r(S) = S ∪ {r}`, and let `h_r` be persist's update: invalidate `touches(r) ∩ reads` and recompute only those.
The cache is admissible iff `v ∘ T_r = h_r ∘ v` for every `S` and `r`. Monotone joins (`one`, `pick=max`, union,
sum) close the square with `h_r` = merge one element, at O(1) or O(log n). Non-monotone reads (`no`, `not`,
`unless`, latest-wins, anything a withdrawal undoes) close it only when their invalidation edge is present: the
`DepKey` of the row whose arrival flips them must be in the answer's `reads`. That is why the `Slot` key exists.
A missing edge is exactly a witness pair: two held sets with the same cache state, split by one arrival.

**No history dependence in `h`.** Persist's update may not read "what the cache held last" except through the
keys the square names (§4.1, the warm-start lesson). A cache built in any order of the same rows must have the
same `digest`.

**Stratification makes the cones finite.** At load, the kernel builds the graph "family F's guard or fold reads
family G" from the guard cells (`one X@…`, `set(ref:*) X@…`) and the fold `reads=` clauses. Standing and roster
are stratum 0. A cycle is a load error naming the cells involved. CC's tables already assert that no row's
admission requires a row whose own admission requires it back (`transitions.json` `_meta.guards.well_founded`,
longest chain 1 [T]), so today's tables load.

### 5.5 Batches

```rust
pub fn step_batch(&self, src: &dyn HeldSource, rows: &[RowView], ctx: &Ctx) -> Vec<Answer<Verdict>>;
```

Within one call the kernel memoizes each `DepKey`'s fold. A batch of 50 key grants into one room reads
`Roster(room)` once, not 50 times. This is the fix §11 measures, and the store-side half of it already landed in 61.4.0 (§11.4).

### 5.6 Effects and their acknowledgement

```rust
pub struct Effect {
    pub id: EffectId,              // H(rule cell ‖ sorted cause RowIds ‖ target): the same act has the same id everywhere
    pub act: Act,
    pub cause: SmallVec<RowId>,
    pub rule: RuleRef,
    pub due: Micros,               // first-held of the cause + the named window, or the cause's first-held
    pub kind: EffectKind,
}
pub enum Act {
    DestroyBytes { content: Digest },
    DestroyKey   { key: KeyRef },               // crypto-shred an epoch or content DEK
    CeaseReplication { peer: KeyHash },
    DeregisterPeer   { peer: KeyHash },
    CancelWatch      { watch: RowId },
}
pub enum EffectKind { Irreversible, Idempotent }
```

- **Stop serving is not an effect.** It is the view `served: bool`, which persist reads at serve time. CC's
  `do stop_serving` becomes a `read` effect.
- **Idempotent** acts may simply run again on the next evaluation; the id deduplicates them in persist's
  executor queue.
- **Irreversible** acts are acknowledged: when persist finishes one, it signs a local-tier `purged` row with
  `refs = [effect id]`. The next `react` sees the acknowledgement and stops returning the effect. A crash
  between doing and signing re-runs an act that is already a no-op (destroying absent bytes).
- **Effects never undo.** If a new rule version would not have caused a done effect, the kernel returns
  `Notice::EffectNoLongerJustified { effect, by: RuleVersion }`, and persist surfaces it.

### 5.7 Drafts and the fixpoint

```rust
pub struct Draft {
    pub id_seed: [u8; 32],         // H(rule cell ‖ cause RowIds ‖ recipient): deterministic
    pub family: FamilyKey,
    pub signer: DraftSigner,       // Node | SpeaksFor(IdentityHash)
    pub body: DraftBody,
    pub holes: SmallVec<Hole>,     // what only persist can fill
    pub cause: SmallVec<RowId>,
    pub rule: RuleRef,
}
pub enum Hole { WrapDek { dek: DekRef, to: KemKeyRef }, Signature }
```

Persist fills each hole (a KEM wrap or a signature), then offers the signed row to **the same door** as any
other row. The rule "a row a clock or a fold causes is emitted by the door the causing row first entered"
(`reactions.json` `_meta.one_emitter` [T]) is preserved because the cause's door is `by=node` context.

**Termination.**

1. A draft's id is a function of `(rule, causes, recipient)`, so a second emission of the same draft is
   `AlreadyHeld` at the codec, before the kernel runs.
2. At load, the emit graph from `reactions.json` (family → emitted family) must be acyclic once self-loops on a
   distinct cause are excluded. This is checked with the strata, and a cycle is a load error.
3. Each round adds rows whose ids are drawn from the finite set `rules × subsets of held rows`, and only causes
   that are new this round produce new drafts.

So the fixpoint is reached in at most `depth(emit graph)` rounds. **CC checked this ("no halting edges"):** there
are no cycles between families in the typed rules, the **longest emission chain is 3**, and the **9 in-family
self-loops descend by leaf**, so each terminates on its leaf order [T as reported by CC under Eric's delegation;
this corrects my earlier "1", which checked only the effect list]. The kernel re-checks the same property at load
and refuses a table that breaks it. Persist asserts ≤ 3 rounds per batch.

### 5.8 Rule version

```rust
pub struct RuleVersion {
    pub cc_tag: &'static str,                 // e.g. "v1.0-rc18"
    pub tables: [(&'static str, [u8; 32]); 6] // sha256 of each manifest the kernel compiled
}
```

- **Pinned at build.** Persist vendors CC files byte for byte. Today that is 13 files at rc18 (`91e430ac` [T]),
  including `governance_policy.json` (`src/federation/namespace/` [T]) but not `transitions.json`,
  `reactions.json` or `family_model.json` [T]. A build step compiles them to static tables, and a from-disk gate checks the hashes. That is
  FINAL_REFACTOR §5.2 unchanged. `Tables::load_all` in the cewp-kernel already verifies sha256 per file
  (`tables.rs:1212-1241` [T]).
- **Carried on every answer** (`RuleRef`), so a client comparing two nodes' views sees whether they ran the
  same rules.
- **Mismatch surfaced, never silenced.** Persist publishes its `RuleVersion` in the `system:` self-report a
  node already makes (a `by=node` row). A peer whose version differs gets
  `Notice::PeerRules { peer, theirs, ours }`. Rows still replicate, because rows carry no rules. Only views can
  differ, and the notice says so.
- **On upgrade:** drop the answer cache, recompute, and diff the old views against the new ones. The diff is the
  changelog of behaviour, and any `EffectNoLongerJustified` notices go in it.

### 5.9 Routing: hold, offer, serve, relay, park, discard (one answer, with the peer as an argument)

**The widening (Eric).** "This is where we analyze how edge knows when to copy what where and make IT part of the
kernel, because it is the same rules." Placement and replication are kernel outputs, not a second engine. The
rules that decide whether a row may be held (audience, scope, custody, the reach gate, the set served to a
stranger) are the rules that decide whether it may be sent. Two engines would be the Live-filter-vs-door class
again: a filter that re-derives a verdict disagrees with the door that made it.

**Persist already has half of this as one resolver.** `replication_audience.rs` says "every door that asks 'may
this node hold, receive or be sent this row' answers through here, so the sender's set, the receiver's hold
decision and edge's serve gate cannot answer differently" (module doc) [T]. Its parts:

| today | anchor | what it answers |
|---|---|---|
| `may_receive(dir, recipient, row) -> Verdict { Yes(Reason) \| No(Reason) }`, `Reason ∈ {Origin, RefersTo, Public, Cohort, NotInAudience, Malformed}` | `replication_audience.rs:664-710` [T] | may this peer have this row |
| `audience_nodes(scope, target) -> Audience { Everyone \| Nodes(set) }`, built from owners' `consent:replication` allow lists and the occurrence's signed `device_class` | `:563-591`, module doc [T] | who the row reaches (the fan-out) |
| `is_public_group` | `:457` [T] | the commons and public groups reach everyone |
| `would_hold` (local or family author always; refuse non-party; under disk pressure refuse proxy content) and `HoldBreadth { OnDemand, ForCohort }` from serve standing | `replication/hold.rs:264-290`, `:540` [T] | may this node keep it, and how widely it holds for others |
| `policy_for(EnvelopeKind)`, `REPLICATION_POLICY_HASH`; "Edge exports its serve/advertise half; CIRISServer pins both" | `replication_policy.rs:431`, module doc [T] | the per-kind admission policy, pinned across the triple |
| `settle_if_held` | `replication_policy.rs:651` [T] | a held re-offer is idempotent success (transport, stays persist's) |
| `cosign::may_receive` | `cosign.rs:1254` [T] | the cosign rows' audience (current members) |

All of these read held rows (owners' grants, occurrences, rosters, charters), so they are folds, and they move into
the kernel as one answer:

```rust
/// Who is asking about the row. Only a key id crosses: the kernel derives the party's principals,
/// node class and memberships from held rows (occurrences, consent:replication grants, rosters).
pub enum Party<'a> { Me, Peer(KeyId<'a>), Stranger }

#[non_exhaustive]                  // until Edge's census of copy decisions lands (hook below)
pub enum Route {
    Hold,                          // Me: keep it (party to it, in audience)
    Offer,                         // Peer: advertise or push; the peer is in the row's audience
    Serve,                         // Peer/Stranger: hand it over if asked, never push (public / served set)
    Relay { custody: CustodyRef }, // Peer: carry it for others as a custodian (HoldBreadth::ForCohort, sealed bytes)
    Park { until: KeySet },        // not yet decidable: the deciding row is missing (the `again` reading)
    Discard { reason: Token },     // never: Retry::Never reasons only (NotInAudience after a terminal fold, Malformed)
}

impl Kernel {
    pub fn route(&self, src: &dyn HeldSource, row: &RowView, party: Party, ctx: &Ctx) -> Answer<Route>;
    /// The fan-out: every party `route` would answer Offer or Relay for. Same fold, enumerated.
    pub fn audience(&self, src: &dyn HeldSource, row: &RowView, ctx: &Ctx) -> Answer<Audience>;
}
```

**One rule, three readings.** `route(row, Me)` is the receiver's hold decision. `route(row, Peer(p))` is the
sender's offer and serve gate. `audience(row)` is the fan-out. They are the same fold, so they cannot disagree,
and the digest (§4.1 #4) proves it per fixture. `Answer.reads` gives Edge its invalidation for free: when a
`consent:replication` grant, a roster or an occurrence changes, exactly the rows whose audience read it
re-route. That replaces audience recomputation on every advertise.

**Order-independence carries over.** `Park` is the `again` reading for routing: a row whose audience depends on a
membership not yet held is parked, not discarded. Today `would_hold` refuses non-party content outright
(`replication/hold.rs:528-531`, the `would_hold` doc) [T]. That is correct only when non-party is terminal, so the kernel answers `Discard`
only when the fold says so and `Park` while a deciding row could still arrive.

**What each layer still owns.**

| | owns | why it is not the kernel's |
|---|---|---|
| **kernel** | the answer `Route` per (row, party), the `Audience`, and their read sets | it is the same rules as the door |
| **persist** | the held store; first-held stamping; the settle; **quotas** (the per-peer write budget); **disk pressure** (`DiskPressureSnapshot`, `hold.rs:512-520` [T]) as a *deferral* that is retryable and never a `Discard`; the bounded `Park` inbox; serving bytes from storage | operator and resource state, never row state. A pressure refusal must stay retryable or the held set cannot converge |
| **Edge** | transport and the actual send; peer discovery, liveness and reachability; scheduling, batching, bandwidth and retries; the want-set and pull protocol (`known_hashes`, set difference); which of several eligible peers to ask first | it is about the network, not the rows. Edge never re-derives a `Route`: it asks |

**Hook for Edge's census.** Edge is running its own census of copy decisions. To join the two:

1. Each Edge copy site is listed as a row of `edge_copy_sites` (site, `file:line`, the question it asks, the
   inputs it reads).
2. A site whose inputs are rows plus a peer key plus first-held instants maps to one `Route` arm and moves into
   the kernel, and the site becomes a `route` call.
3. A site that reads anything else (liveness, RTT, link cost, a local cache of "what I sent last") stays Edge's.
   If it changes *whether* a row may be sent, rather than *when* or *via whom*, it is a breaker of the §3 kind
   ("what I processed last", §4.1) and goes to CC as a worklist item.
4. `Route` is `#[non_exhaustive]` until that census lands. A new arm needs a CC cell (W8) and a vector.
5. `REPLICATION_POLICY_HASH` becomes the hash of the kernel's routing tables, so the triple pin persist, Edge and
   Server already share (`replication_policy.rs` module doc [T]) pins the rules themselves.

### 5.9a Park deadlines per origin (persist's proposal, for CC to type as the placement cell, W8)

Every `Park` and every waiting `Inert` carries a lapse (§5.3). CC asked what deadline persist wants per origin.
The proposal below starts from the release lead's draft and changes two things: the member-peer deadline is tied
to the row, and the quotas are sized from the canonical.

**The facts that size it.**

- **W is the natural maximum.** Under the rc19 W rule (§1), a row first held more than W after its signed
  instant does not count without a vouched past. A parked row dropped and re-offered later gets a **new**
  first-held instant (the old one died with the copy). So past `asserted_at + W`, a re-offer re-admits a
  standing-dependent row only with a vouch, and holding it longer buys nothing. That corrects the draft's "a later
  re-offer re-admits": it does so only within W, or with a vouch.
- **Intake (canonical, §13.2a).** Peak month Oct: ~17.4k admitted rows across the five largest families. The mean
  row is ~11 KB (6.6 KB average envelope + 4.5 KB signature). That is ~580 rows/day and ~6.4 MB/day at peak.
  Free space never returned is 333 MB (§13.2b), so any parked-copy budget must also be reclaimable (S1).
- **The existing write quota.** 600 writes per peer per 60 s (`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`,
  `replication/admission.rs:198`, `:212`) [T]. It bounds rate, not parked bytes.
- **R1's shadow count is not yet measured.** These are bounds that hold whatever it shows. The count then tunes
  the quotas, never the deadlines.

| origin of the parked or waiting row | lapse | quota | reason |
|---|---|---|---|
| a peer **in the row's audience** (a member) | **`asserted_at + W`** (W = 72 h, CC 2.6.7), and never less than first-held + 1 h | per origin 32 MB (~5 days of the canonical's peak intake) | a member's row is normally ours too, and its parent is normally in flight from the same mesh. Past `asserted_at + W` the row needs a vouch anyway, so keeping it longer is dead weight. The 1 h floor lets an old row that arrives with its parent in one sync round settle |
| a **known** peer that is not in the row's audience (a relay, a mesh server) | **first-held + 24 h** | per origin 16 MB | covers the daily re-ack and reconnect cadence (`HOLDING_CLAIM_REACK_AFTER_SECS` = 24 h [T]). A non-member is carrying rows for others, so if the parent hasn't come in a day the row isn't ours to keep |
| a **stranger** (no registered key) | **first-held + 1 h** | per origin 1 MB (~90 rows); a pool of 8 MB across all strangers | one sync round for a parent in flight (typically the key record itself). Strangers can't be told apart, so their pool is shared and small |
| **global** | | a park inbox of 128 MB (~20 days of peak intake; ~7% of the canonical file) | an operator setting that decides storage, never a verdict (FINAL_REFACTOR §5.1 tier 3) |

**CC accepted this table as the W8 placement cell.** Lapses and quotas are **storage, never a verdict**. They
decide whether this node keeps a copy, never what a row means. Named property **P-QUOTA (quota independence):
two nodes with different quotas and lapses reach the same verdict on every row they both hold.** A row one node
dropped at lapse is simply not held there; it never becomes "refused" there. Harnesses 3 and 4 (§6.2) check
P-QUOTA by running each fixture under two quota profiles (the table above, and every quota at 1 row with every
lapse at its floor) and comparing digests over the intersection of the rows held.

**On lapse:** drop the local copy, count it as `persist_park_lapsed_total{origin_class, token}`, and keep nothing
but the counter. Dropping is a storage act, not a verdict. The row stays re-offerable, and a re-offer is a new
arrival with a new first-held instant. **On quota:** the oldest parked row of that origin lapses first. It is
never refused at the door, so a flood ages its own rows out.

**Terminal `Inert`** (`Retry::Never`, e.g. a stranger's owner binding that counts for nothing, CC 3.2) is not
waiting, so it needs no lapse. It is held only where `route(row, Me)` says `Hold` (party and audience). Otherwise
it is `Discard`. That keeps CC 3.2's "held and counts for nothing" for rows the node is party to, without letting
strangers fill the store with permanently inert rows.

`CC`'s `placement` column is a gap for 156 of 184 families [T, `_meta.coverage.placement`], so today almost every
family takes the default (§10 W8).

---

## 6. Question 4: the developer experience

### 6.1 Adding or changing a rule

| change | where | persist work |
|---|---|---|
| a role, policy, guard, change, undo or confirm cell | CC `formal/derivation/*_text.tsv` → `transitions.json`, plus vectors | vendor at the CC tag; the build regenerates the tables; the differential (§6.2) reports every verdict that moved |
| an expiry, clock, reaction or emit | CC `reaction_text.tsv` → `reactions.json` | the same; a new `Act` variant is the only Rust change |
| a fold or count | CC `fold_text.tsv` / `count_text.tsv` → `family_model.json` | the same, if the fold grammar already has the clause |
| a new fold primitive (a tally, a walk) | Rust in the kernel, with a CC reference and a merge-law test | it has no column until CC writes one; FINAL_REFACTOR §5.4 already treats a primitive with no column as a defect |
| a new storage column or index | persist | none in the kernel; `touches` and `HeldSource` name keys, not columns |

A ruling therefore appears in persist's review as a vendored JSON diff plus the differential's output. It does
not appear as a gate diff.

### 6.2 Testing storage against the kernel

There are six harnesses. They are named here and not built.

1. **Vectors.** CC's `mesh_story_trace.json`, `governance_policy_vectors.json`, `namespace_match_vectors.json`,
   and one vector file per `formal/` model's checked traces (each model already enumerates its runs, e.g. 47,296
   per reading for `owner_binding` [T, README]). The kernel and every host run them.
2. **Shadow differential.** A recording wrapper around persist's `AttestationStore` (and each `*Store`). At
   every door call it also runs `kernel.step` over the same held set plus the candidate and logs both outcomes.
   It runs over the existing 119 `*_invariants.rs` files [T, `ls | wc -l`], the 34 `tests/*.rs` and
   `store/backend_suite.rs`, on every backend. It changes no behaviour, so it can ship in 61.x behind a feature
   flag.
3. **Permutation run.** For each fixture's row set (up to 6 rows: every order; above that, 200 seeded orders),
   offer the rows to a fresh store in each order and compare the kernel's output `digest`. This is the kernel's
   P5/D6/G11. A failure is a witness pair. The harness asserts that each shuffle is a permutation and not the
   identity (Holon's "plant is vacuous" check, §4.1 #5). It also runs each fixture under two quota and lapse
   profiles and compares digests over the rows both hold (**P-QUOTA**, §5.9a).
4. **Commuting square.** For generated `(S, r)`: `cached_answer(S) ⊕ invalidate(touches(r))` against
   `fresh_answer(S ∪ {r})`. This is the certificate the answer cache must hold (§5.4). Under P-QUOTA, a lapse is a
   removal from `S`, and the square must close for removals as for arrivals.
5. **Planted mutations.** `KernelMutation` (§4.1 #8). The must-convict set has to move a digest or fail a vector:
   `DropOnRefuse`, `StampAtDoor`, `LastProcessedWarmStart` (a cache that remembers its last update), and
   `MissingInvalidationEdge` (drop a `Slot` key from `reads`). The must-not-move set has to leave every digest
   equal: `ReverseInput`, `ShardFolds`, `ColdCache`. Only the two halves together are evidence.
6. **Set-encoding equivalence** (CC's law for set objects, §13.6a). The digest of `fold(held ∪ {item})` must
   equal the digest of `fold(held ∪ leaves(item))` under shuffles and partial leaf sets. A family that fails it is
   not a set family.

The SQL `lifecycle_predicate` (FINAL_REFACTOR §6.2) joins harness 2: the predicate and the kernel's `view` run
over the same rows, and any difference is reported.

### 6.3 What a divergence report looks like

```text
DIVERGENCE kd-0042   class=ORDER(a)   family=delegates_to/owner_binding   rule=rc18:transitions#owner_binding.attest
  rows      r1 = owner_binding(A→node) first_held=t1   r2 = withdraws(r1) t2   r3 = owner_binding(B→node) t3
  witness   same set {r1,r2,r3}
            order (r1,r2,r3): door ADMITS r3 → owner_of=B
            order (r1,r3,r2): door REFUSES r3 (admission.rs:13091 single_node_owner) → owner_of=None, for good
  kernel    both orders: r3 Live, owner_of=B; reads={Keys(node), Refs(r1)}
  ruling    CC C557 (text_conflicts.tsv:558): reading "again/unowned" holds O1–O6
  verdict   DOOR WRONG   → fix lands with its CC cell id; token `federation_owner_conflict` retired
```

In the frame of §4.2: `S₁ = {r1}` then `r3` arrives, against `S₂ = {r1, r2}` then `r3` arrives. The door's
state agrees on "r1 is the live owner" in both, and one arrival splits them for good. That is a witness pair
against the door's `h`. The kernel closes the square because `owner_of` is a fold, not a stored answer.

Every report has the shape (set, two orders or two sets, door outcome, kernel outcome, reads, the CC cell, and the
two digests).
It is triaged into one of three outcomes, as FINAL_REFACTOR §6.3 does: **door wrong**, **kernel wrong**, or
**different question** (listed with its reason).

### 6.4 Native and WASM

The cewp-kernel has zero external dependencies (`Cargo.toml` `[dependencies]` empty [T]) and builds to WASM. The
converged kernel keeps that: `#![no_std]` plus `alloc`, with a small vendored sha256 for table verification only
(the cewp-kernel has one, `tables.rs:929` [T]). Holon runs one mathematics under two storage policies, a
compile-time arena for sealed scenes and a runtime arena for hosts (`CIRIS_HOLON_ENGINE.md`, "Two storage
policies" [T]). The kernel takes the same approach:

- **baked**: tables compiled into `static` arrays by build step. Used by persist, Edge native and the CLI. No
  JSON parsing per row.
- **loaded**: `Kernel::load(&TableBytes)` parses the vendored JSON at start. Used by the browser and CEWP's sim.
  It is the same evaluator.

A gate asserts that baked and loaded produce identical `RuleVersion` and identical vector results. Holon's fences
are copied (§4.1 #8): a dependency allow-list that fails on any new name; `no_std` builds for
`wasm32-unknown-unknown` and `wasm32-wasip1`; and the vectors **run** on the WASM artifact, with a gate that
fails rather than skips when the runner is missing.

### 6.5 Cost per row

Cost is now its own section (§11): the floor, the bound per rule class, and the three gates.

---

## 7. Converging with the CEWP kernel

The CEWP reference kernel (`cewp-kernel`, "Authoritative CC §4.5.13 state processor in pure Rust", `lib.rs:1`
[T]) and persist's kernel must run the same rules. Today they cannot:

| | cewp-kernel | needed |
|---|---|---|
| tables | rc17 `b363b6e`: 191 families, 474 transitions, no `guard`/`change`/`undo` cells; no `reactions.json`, no `family_model.json` (`docs/kernel/tables/VERSION` [T]) | CC tip: 184 families, 459 transitions, 26 guarded, 20 changed (`transitions.json` `_meta` [T]); plus reactions and fold/count |
| row | `Row` with string fields; `asserted_at` defaults to 0 when absent (`lib.rs:63` [T]) | `RowView` (§5.2); a missing signed instant is malformed, not 0 |
| door | drops on refusal (`processor.rs:1078-1084`) [T] | never drops (§5.3) |
| object family | first by `asserted_at` claims the id (`processor.rs:80-87`, `:968-972`) [T] | a family is a property of the row; the object id includes the family, or a mismatch is inert, never a claim |
| cost | full refold per step [T] | read sets plus `HeldSource` (§5.4) |
| rules it cannot type | `Rule::Prose(String)` returns `None` from `votes` (`types.rs:43-87`) [T] | `Verdict::Unserved { cell }` (§5.3) |
| windows | from `first_held` [T] | the same |

**Path.**

1. **One crate.** Lift `cewp-kernel` into a shared repo (or keep it in CEWP) as `ciris-kernel`, with the §5 API.
   Persist depends on it. Persist's `RowView` adapter from `Attestation` stays in persist.
2. **One table set.** Both vendor the same CC tag, all six manifests. `RuleVersion` equality is a CI check in
   each consumer.
3. **One vector set, owned by CC.** The `mesh_story_trace` parity test (`lib.rs:91-` [T]) becomes one of many.
   Persist's differential (§6.2) exports every divergence it settles as a new vector upstream, so CEWP's sim
   inherits persist's real row shapes.
4. **cewp-sim keeps its mesh.** `Mesh` (`mesh.rs` [T]) is a host, as persist is: it supplies first-held instants
   and runs effects.

---

## 8. Question 5: what persist refuses to give up, and what it would delete

**Persist keeps:**

- bytes at rest, the at-rest cascade, and key states (Enabled, Disabled, Destroyed);
- the codec, canonical bytes, `RowId`, and the right to refuse malformed and unverifiable input;
- hybrid verification and KEM; private keys never cross into the kernel;
- replication, the settle, quotas and placement's bounded inbox;
- first-held stamping, written once;
- the effect executor and the signing of acknowledgements and drafts;
- SQL indexes and paging, with predicates generated from the kernel's rules and witnessed against them;
- schema and migrations (but no held-row rewrites);
- the local operational store (sequence, tasks, secrets, telemetry);
- **the right not to sign** an inert act of its own.

**Persist would be glad to delete:**

| what | size today |
|---|---|
| the `check_*` gates whose rule moves into a CC cell | 180 distinct fns [T]; `admission.rs` alone is 32,640 lines with 282 top-level fns [T, `wc`/grep] |
| the `withdraws_admission_rule` stamp and `withdraws_depth` | B2, B15 |
| per-feature receipt tables (V199 self-roster, V213 vote windows, V214 cosign hold) | replaced by one first-held column [T: `first_held` lives in those tables, `attestation_admit.rs:1442-1452`] |
| the epoch counter table | B7 |
| node-emitted `hard_case` rows | 20 call sites [T] |
| seven clocked sweeps | §2.2 #35 |
| `PLAN_INSTANTS` and the instant-parity gate | `store/parity.rs:3444` [T]; nothing in the kernel reads a clock |
| the latest-wins upserts | B10 |
| most of the 119 invariant files' hand-rolled fixtures | they become vectors |

---

## 9. Where this supersedes FINAL_REFACTOR

| FINAL_REFACTOR | this document |
|---|---|
| §5.3 `step(held, row, door, now) -> Result<Admitted<Plan>, Refusal>` | `step` returns `Answer<Verdict>`; there is no `Err` for a held row. `Admitted<Plan>` stays persist's executor type, and an inert row also gets a plan (store it) |
| §5.3 "there is no third outcome" | there is one: `Unserved`, for gap and prose cells, distinct from both |
| §5.6 "a refused row never enters the held set" | true only for persist's codec and placement refusals; a kernel refusal is held and inert |
| §5.8 "admit both; the fold decides" (as a list of named deltas) | the rule for every door, made structural: the kernel cannot drop |
| §6.1 `Folded<T> { value, rows, rule }` | `Answer<T>` adds `reads` and `valid_until`; those two are what make it incremental |
| §5.7 `FamilyKey` computed by persist | computed by `Kernel::classify` from CC's registry |
| §5.2 vendored manifest compiled to static tables | unchanged; now also `reactions.json`, and the same tables feed CEWP |
| §12 proof | adds the permutation run and the commuting-square harness (§6.2 items 3 and 4) |

Everything else in FINAL_REFACTOR (the row view, CBOR/COSE, the dialect engine, the surface, the schema baseline)
is orthogonal and stands.

---

## 10. Worklist for CC

These are decision sites whose rules are not yet typed in CC's manifests, in priority order. The coverage
numbers come from `transitions.json` and `family_model.json` `_meta` and cells at `7b86bee` [T].

| # | item | today | ask |
|---|---|---|---|
| W1 | **C557 owner binding: RULED, landed** | Eric; CC 3.2 at rc19 `8694fc1` [T] | only bindings the node's own key cosigned count; exactly one is the owner; any other count is unowned; a stranger's binding is inert (B1). Remaining for CC: type it as a fold cell on the owner-binding family, so the kernel reads it from the table |
| W2 | **uniqueness guards that refuse** | 8 `no X@admitted … else refuse` clauses in 5 families [T] | a `tie_break` cell for each (CC#203), so the duplicate is held and inert |
| W3 | **guards** | 26 of 459 transitions typed; 433 `generic` [T] | type the 21 non-set-function sites in §2.2 first: 5-7, 9, 11, 12, 14, 15, 19-24, 26-30, 33, 34. Each names a persist anchor to read |
| W4 | **W / C565: RULED, landed** | CC 3.3.4 (standing), 4.5.13 (lift window), 4.5.3 (reversal ahead of notice; "not held here" + refetch) at rc19 `8694fc1`; model `KernelWorldSigned.tla` [T] | remaining for CC: type the freshness cell (174 `generic` today [T]) with that test, and name the vouched past (CC 3.3.4) as the `Inert` cure so the kernel can put it in `missing` (§1, B5) |
| W5 | **folds and counts** | fold: 76 `cc-table`, 108 `generic`; count: 16 `cc-table`, 164 `generic`, 4 `gap` [T] | type the folds the kernel needs first: `owner_of`, epoch identity (W7), group head chain, cosign pending/assembled/lapsed, peer record conflict |
| W6 | **emit or notice: DERIVED** | 25 emits, including 15 `hard_case:*` [T]; 7 `not_yet_by_origin_door` [T] | the rule: what every node can read from rows plus its clock is a notice; a signed row remains only where someone outside the node must be told or held to it (key grants, `consent:state:expired`, `consent:decay:*`, the CC 3.4.13 safeguarding escalation, the takedown/purge tombstone). CC will type all fifteen kinds |
| W7 | **epoch identity** | `formal/key_plane` K6 states when an epoch changes, not what names it [T] | name an epoch by the digest of its departure rows, not a counter |
| W8 | **placement and routing** | `placement` 156 of 184 `gap` [T] | placement, audience, custody and the stranger-served set as typed cells, so `route` (§5.9) is a table read for every family, not code. Edge's census of copy decisions feeds the same cells |
| W9 | **operator settings in verdicts** | `withdraws_depth` (V157) [T] | a governance-policy number, or delete the dependence |
| W10 | **effect vocabulary** | `do` acts: `cancel_watch`, `cease_replication`, `deregister_peer`, `drop_held`, `stop_serving`, `destroy_bytes` [T] | mark each `irreversible` or `idempotent`; recast `stop_serving` and `drop_held` as views; add `destroy_key` (crypto-shred), which persist does on a sweep today (`community_dek.rs:1137` [T]) with no reaction naming it |
| W11 | **acknowledgement row** | `purged` and `sealed` are new event words [T] | bless `purged` (local tier, `refs=[effect id]`) as the acknowledgement of an irreversible effect (§1) |
| W12 | **clock guards** | `within(accord_halt)` and `after(moderator_election)` [T] | say which instant each reads (first-held of which row) |
| W13 | **the ruled column** | roles 146 / policy 146 `code-v61`; signer_rule 122, subject_rule 164, cosign_rule 169, lifecycle 181 `code-v61`; undo 30 `gap`; roles 2 `gap` [T] | as FINAL_REFACTOR §5.5: each `code-v61` cell is step 1 (state today). The differential gives step 2 for free |
| W14 | **reader trust set** | 32 folds `by=reader` [T] | specify the input: reader key and accepted roots, or the reader's own trust rows |
| W15 | **CEWP tables** | rc17, no guards, no reactions [T] | one tag for both kernels (§7) |
| W16 | **exact numbers (COSE float gap)**: **protocol half DONE** at rc19 `6453665` (whole-number weights and threshold; `custom:` removed). Open for row `weight`/`score` | `weight: Option<f64>` (`types.rs:1645`) and f64 rubric sums (`consensus.rs:418`) [T] | type every score, weight and threshold as an integer fixed-point or a rational on the wire, so the kernel never sees a float (§4.1 #3) |
| W17 | **cost classes** | none published | per-transition and per-fold `CostClass` via `tools/kernel_cost.py`; the build refuses a mismatch (§11.2) |
| W18 | **the census-family guards still refuse** | `census:*` folds already carry `pick=once(…)` tie-breaks [T, fold cells], but their guards still say `no … else refuse` (B18) [T] | make the guard defer to the fold's `once` tie-break, so the table stops stating the rule twice |
| W19 | **multi-row items: YES, as a set object** (rc19 `6453665`; five conditions, §13.6a). Open: CC's `key_plane` model of the group key before the text moves | the key-grant set carrier was retired at rc7 (`key_grant.rs:17-18`) [T]; custody is one row per blob per day [T] | rule on I1-I4 (§13.5): a set claim for custody, a group KEK for self/family that rotates on member removal and device revocation, a history grant on join, and a re-admitted, per-leaf-addressable wrap set |

---

## 11. Performance: the floor, the bound, the proof

Eric's requirement, verbatim: "we need that kernel to approach the theoretical limit for performance for
RUST/WASM and provably result in persist performing better post refactor". This section says what the limit is,
what bound the kernel is held to, and the three checks that make "better" a gate rather than a claim.

### 11.1 The floor, and how far above it persist runs today

**The floor per admitted row** is what no decision layer can remove:

- one hybrid signature (sign on emit, verify on ingest), where ML-DSA-65 dominates;
- canonicalisation and hashing;
- one durable write, amortised by batching commits.

**Measured.** The instrument is `src/federation/kg_burst_measure.rs` on branch w614 (`912e404c`, 367 lines) [T, I
read the file]. Every test in it is `#[ignore]`. It prints `KGBURST` lines with `plan`, `sign` and `put` split per
emission, plus `wrap150` and `grant_put150` (`:305-330`) [T]. The per-operation numbers below are the release
lead's run of it (TESTED by them; the KGBURST output is not committed, so I could not re-read the raw lines).

| operation (v61.3.0, before the 61.4.0 fix) | sqlite | postgres | source |
|---|---:|---:|---|
| hybrid wrap, X25519 + ML-KEM-768 | 0.2 ms | | lead's kg_burst run |
| stamp + canonicalise + hybrid sign | 1.3 ms | | lead's kg_burst run |
| member-grant insert | 0.3 ms | 0.26 ms | lead's kg_burst run |
| **floor, emit side** (wrap + sign + insert) | **~1.8-2 ms** | | sum of the three rows |
| per-row admission check + insert, 50 members | 79 ms | 274 ms | lead's kg_burst run |
| per-row emit, 1-member room | 13.6 ms | | lead's kg_burst run |
| per-row emit, 50-member room | ~99 ms | | lead's kg_burst run |
| 150-row emission (50 members x 3 devices), whole burst | 17.8 s (119 ms/row) | 36.9 s (246 ms/row) | 61.4.0 CHANGELOG, "medians of 3, `kg_burst`" (w614 `bfad9816`) [T] |

**Two corrections to the brief.**

1. **The two sources disagree.** The CHANGELOG's whole-burst medians give 119 ms per row on sqlite and 246 ms
   per row on pg. The per-row figures give ~99 ms on sqlite and an admission share of 274 ms on pg, which is
   more than the pg whole-burst per-row cost. The runs differ (median of 3 against one run, and burst against
   per-row), so neither number is wrong, but the KGBURST lines should be committed beside the instrument so one
   recorded run backs every figure. I use the ranges.
2. **The build profile.** The brief says "deps at opt-level 3, crate at opt-level 0". I found no
   `[profile.dev.package]` or `opt-level` override in `Cargo.toml` or `.cargo/config.toml` on either worktree
   [T, grep]. So the override, if there was one, came from the environment [B]. If the dependencies were in fact
   at opt-level 0, then the crypto "floor" is inflated as well. Either way, persist's own decision code ran
   unoptimised, so the 13.6 ms overstates what release would show. A release-profile run is needed before any
   ratio is quoted outside this document.

**Decomposing the 1-member 13.6 ms** as far as the code allows. 13.6 − (0.2 + 1.3 + 0.3) ≈ 11.8 ms is not
crypto or the write. What the code shows runs per row in that remainder:

| component | evidence | share |
|---|---|---|
| the attestation door's gates: about 57 calls in `plan_put_attestation` (`attestation_admit.rs:694-1404`) [T], several doing directory reads | read [T] | unmeasured |
| each directory read crosses `block_on` + `spawn_blocking` + a connection lock on sqlite; `benches/storage_floor.rs` exists to split exactly this tax from the raw write (module doc) [T] | the bench exists [T]; no baseline is recorded in-repo [T] | unmeasured |
| the key-grant planner and admission: `recipient_may_hold_key` (`key_grant.rs:826`), `check_key_grant_row_admission` (`:1157`) → `check_sealer` (`:998`) → `is_active_member_at`, and the AV-45 write-scope gate. Each folds the roster and lists every member's occurrences per row (61.4.0 CHANGELOG) [T] | read [T] | in a 1-member room the fold is small; this is what grows to ~99 ms at 50 |
| envelope JSON: gates read `serde_json::Value` paths (e.g. `envelope_dimension`, `admission.rs:2074`) [T], and `compute_persist_row_hash` re-serialises | read [T] | unmeasured |

**The bench that would close this.** `benches/attestation_door.rs` (it does not exist). It would run
`plan_put_attestation` over a 1-member and a 50-member room in release, with a `tracing` span per gate tier
(AV-76 tiers 0-5 are already marked in the source), reporting per-tier µs and the count of directory reads per
row. The other benches have no recorded per-row baselines for this path. `sign.rs` measures Ed25519 only, at
about 100 µs in software (module doc) [T], not ML-DSA-65. `ingest_pipeline.rs` cites 768 trace rows in about
9 ms in release (module doc) [T], but that is the trace path, not the attestation door. `occurrence_registry.rs`
cites 150-215 µs upserts (module doc) [T]. `storage_floor.rs` and `scores_read.rs` record no numbers in source [T].
`sign.rs` should gain an ML-DSA-65 sign and verify case so the floor is measured by a bench, not inferred.

**What the floor means for the target.** The kernel's job is to make decision cost per row a small, bounded
fraction of the floor. Proposed budget: **decision cost ≤ 10% of the floor per row in release** (≤ 0.2 ms
against ~2 ms), held per cost class in §11.2. Today the 1-member gap is about 6x the floor and the 50-member gap
about 50x [T on the arithmetic of the lead's numbers; the profile caveat above applies].

### 11.2 The bound, per rule cost class

The kernel is held to a cost class per rule cell, not per family. Counts are from CC tip `7b86bee`.

| class | members (CC's counts; mine where they differ) | today's typical cost in persist | kernel bound (incremental) |
|---|---|---|---|
| guard `one X@admitted[…]` | CC 25; my regex over guard strings counts 30 occurrences of `one` [T] | a directory query per row | O(log n): one `Slot` index probe |
| guard `no X@admitted[…]`, negated role tests | `no` 8 [T]; `not` 9 [T] | a query at the door, then **drop** | O(log n) to evaluate. **Non-monotone**: needs a `Slot` invalidation edge, because the arrival of an `X` flips it |
| guard `each`, `set`, `all` | `each` 11, `set` 2, `all` 1 [T] | a loop of queries | O(k) in the named set; maintained per element |
| fold `pick` max or rank (latest-wins, the precedence ladder) | CC: max 13, rank 8. My count is max 15, rank 8 (the regex classed a combined rank-then-max pick as max) [T] | `ON CONFLICT … WHERE excluded.asserted_at >` (B10) or a read-time fold | O(1) amortised per arrival (a join); **non-monotone under withdraw**, so keep the per-object candidate set ordered: O(log c) |
| fold `pick=chain(prev_head_digest)`, `once`, `pair`, `union`, `agree`, `set` | chain 4, union 3, agree 2, once 4, pair 2, set 1, min 1 [T] | held-head replace (B12); refusal | chain: O(1) per link, a fork is a view; union: O(1); once: the tie-break join |
| fold `combine` | median 5, sum 2, min 2, max 1, all 1, policy 1 [T] | various | sum/min/max/all: O(1) or O(log n). **median: an order-statistic tree, O(log n) per arrival and per withdrawal**. `policy`: the two_path count |
| fold `cut` | 11 [T] | read-time filter | O(1) per element, at the partition boundary |
| fold `over` a counted set (standing, person) | 17 [T] | per-row roster refold (the 61.3.0 cost) | O(1) per arrival after one stratum-0 fold per batch |
| reaction with `unless` | 10 of 58 reacts [T] | sweep scans | non-monotone: an invalidation edge on the `unless` event |
| clocks, expiries | 19 clocks, 20 expiries [T] | seven periodic sweeps (§2.2 #35) | O(log w) on a wake heap; no scans |
| **ranked choice** (CC 4.5.13; `moderator_election`, any declared choice, the secret poll's tally) | one summary per choice | no door today (§4.3) | **O(1) per ballot** (resolve `pick=agree`, then add or subtract one cell); **finish O(k · cells) per round, fewer than k rounds**, so at most ~k² · L(k, 3): about 25,600 cell visits at k = 8. Whole numbers only. Cost class `Join` per ballot plus a bounded `Finish` |

**Holding the implementation to it.** Every compiled rule cell carries its `CostClass`. CC will publish
per-transition classes through `tools/kernel_cost.py`, and the build refuses a table whose class differs from the
kernel's own classification. Each class has a bench, so the budget is enforced per class:

```rust
pub enum CostClass { Probe, NonMonotoneProbe, Linear { over: SlotId }, Join, OrderStat, Wake, Finish { rounds_lt: u32 } }
impl Kernel { pub fn cost_class(&self, cell: CellRef) -> CostClass; }
```

**Not in the bound:** a `Linear` guard over an unbounded set. CC's tables bound every `each` by a named set (a
roster or ranks), and the kernel refuses to load an `each` whose set has no declared bound.

### 11.3 "Provably better": three checks

**(a) Asymptotic, per decision site, from the census.** n = held rows in the partition, m = room members, D = the
devices per member, d = the delegation depth ceiling, R = rows per emission.

| site (§2.2 #) | today | kernel | status |
|---|---|---|---|
| key-grant emission (planner + sealer + write scope) | O(R·m·D) per emission at 61.3.0 (61.4.0 CHANGELOG: "re-folded the roster and listed every member's occurrences" per row) [T] | O(m·D + R) | 61.4.0 store-side already gives O(m·D + R) for one emission (§11.4) [T, commit message] |
| self-roster / key-grant / owner-binding W (20-22) | two roster folds per row (`is_roster_key_at` at the signed instant and at now) [T] | O(1) per row after one `Keys(identity)` fold | |
| owner binding (6) | list the node's `delegates_to` granters per row (`live_owner_binding_granters`) [T] | O(1) join on `Keys(node)` | |
| delegation cycle (7) | BFS of ≤ d hops per edge door [T] | the same walk, but only when a `Refs` or `Keys` edge in the cone changes | |
| `withdraws` authority (9) | a delegation walk at the door plus a fold at read [T] | one fold on `Refs(target)`, O(c) composers | |
| cohort standing, consent, no-moderator, subject known (11, 12, 14, 15) | 1-3 directory queries per row, each paying the async hop [B on the count] | O(log n) probes, memoised per batch | |
| cosign execute (19) | a sweep over open receipts, each re-offered through the door [T] | the pending view updated on `Slot(quorum key)` | |
| community epoch (23) | `resolve_community_members` O(m) per mint [T] | shares the `Roster` fold | |
| sweeps (35) | a periodic scan of each table [T] | O(log w) wake | |
| LWW upserts (29) | O(log n) | O(log c) ordered candidates | a constant-factor change, not a class change |
| trust root, consensus (17, 18) | already pure | the same | no change; the cache comes free |

**(b) Differential CI gate: digests equal, time lower.** The same fixtures (the 119 invariant files, the backend
suite and kg_burst) run through today's doors and through the kernel in shadow mode (§6.2 #2):

- **digest gate:** per fixture, the kernel's output digest equals the door-path digest, or the fixture names a
  recorded, ruled divergence (§6.3);
- **time gate:** per fixture class, kernel time is lower than or equal to door time, in release, interleaved A/B
  over several rounds, as a ratio. Holon's rule applies: "a performance claim without a moved benchmark ratio does
  not merge" (`DATA_OBJECT.md`, the benchmark contract) [T]. A family's cut-over (FINAL_REFACTOR §5.5 step 3)
  cannot merge unless its fixtures move the ratio or hold it within noise.

**(c) WASM ratio gate.** The same kernel benches run on the `wasm32` artifact under a pinned runner. The native
ratio is recorded per class, and the gate **fails** if the runner is missing (Holon `ci-gates.sh:852-894`
[T]). The target ratio is near 1x-2x. Holon measured the ordinary WASM cost at 2.1x and **7.9x** when one routine
fell to soft `libm::sqrt` (`engine/PORTABILITY.md:185-192`) [T]. The kernel avoids that class of penalty by
construction: integer-only decision code (§4.1 #3), no float type in the crate, no `HashMap` with a random state
(BTree or a fixed hasher), and no allocation on the hot path (an arena per batch, reset between calls).

### 11.4 What the kernel cannot buy, and what it must not take credit for

Storage and crypto are the floor. The kernel moves neither. Some gains come from the **store side** and are
credited there:

| gain | layer | status |
|---|---|---|
| one fold per emission (`EmissionFold`, `AudienceSnapshot`, `with_roster_read_memo`); one held-check walk; batched member-grant inserts | store-side, 61.4.0 (w614 `bfad9816`, "the 150-row burst is linear in rows") [T, commit and CHANGELOG] | **after-fix numbers: PLACEHOLDER**, to be filled from a committed KGBURST run |
| batched inserts in one transaction; prepared statements; fewer pg round-trips (pg's 274 ms against sqlite's 79 ms admission at 50 members is mostly round-trips [B]) | store-side | not done |
| the async-wrapper tax per read (`storage_floor.rs`'s question) | store-side | unmeasured |
| no per-row refold anywhere (not only key grants), per-class bounds, wake instead of sweeps, digest-checked caches | **kernel** | this document |

The rule: a before/after ratio is attributed to the kernel only on fixtures where the store path is unchanged
between the two arms. 61.4.0 is the store-side down-payment on exactly the kernel's incremental-evaluation
problem, so the kernel's baseline is **61.4.0, not 61.3.0**.

---

## 12. Risks and open questions

- **R1. Held-set growth.** Admit-both holds rows that are refused today (low trust, no standing, duplicates).
  Quotas, placement's `Park`, and `removable` (§3.1) carry that load. It has not been measured. **The measurement
  that sizes it:** in Phase 0, shadow mode counts every refusal the doors make today, by token, family and origin
  (local or replicated), per day on a real node. Those are exactly the rows admit-both would hold. Persist already
  has the hook point: every refusal leaves the plan as an `Err` before the executor. The count, multiplied by the
  median row size (kg_burst prints `row_bytes_median`, `kg_burst_measure.rs:305-330` [T]), is the held-set growth
  per day. Placement and quota budgets are sized from it before any family cuts over.
- **R2. Read-set precision.** A too-coarse `DepKey` (for example, the whole family) invalidates too much, and the
  answer is still correct, only slow. A too-fine key misses an invalidation, and the answer is wrong. The
  commuting-square harness (§6.2.4) is what catches the second case.
- **R3. Generic guards hide gates.** 433 transitions say `generic`. A persist gate with no CC cell has no kernel
  rule. Until W3 lands, the shadow differential will report those gates as "door refuses, kernel admits". Each
  such report is an item for W3, not a kernel bug.
- **R4. Tokens.** Inert verdicts reuse today's refusal tokens. A replicated row that returned `Err` now
  returns `Ok` with an inert verdict. Edge's apply loop and Python callers that `except` on those kinds need an
  adoption note [B: not surveyed].
- **R5. Order.** Following FINAL_REFACTOR §5.5: shadow (no behaviour change) → cut over per family with the
  bespoke gate deleted in the same commit → rule (behaviour change, one named delta per family). Breakers B1-B20
  are all step-4 changes and each ships as its own delta.
- **R6. Routing on Edge's hot path.** `route` is asked per (row, peer), which is more often than the door is asked
  per row. The cost rule: compute `audience(row)` once per row and cache it under its read set, so a per-peer
  `route` is a set-membership test, O(log a). Edge's census (§5.9 hook) has to show which of its copy decisions
  run per frame, so that those are served from the cached audience and never refold.
- **R7. The W residue is visible to users.** Under the W ruling, two nodes can show different standing for a
  late-arriving row until someone signs a vouched past. The `Inert` verdict names that cure, so a client can
  show "waiting for a member to vouch" rather than a silent difference.

---

## 13. The cost ledger

Eric, verbatim: "The purpose being, we can finally optimize what needs to be copied when, what costs the most, what
multi-row items we should be able to support to drastically improve performance either fold or transport, etc."
This section is the ledger: what costs bytes and time, which acts multiply rows, and which multi-row items would
replace N signed rows with one.

### 13.1 Data, and what it is not

**Eric's standing rule: no production data, only aggregates.** Server correctly refused a store copy. The
production numbers are an **aggregate table** and a `dbstat` from the canonical (§13.2a-c), with groups of n < 5
merged. Every other number in this section is **test-shaped**, taken from stores that other sessions' test runs
left on this machine. I
copied each one into my scratch directory first (`sqlite3 -readonly src ".backup dst"` for the seeded store; `cp`
of `.db` + `-wal` for the mesh stores) and ran SELECTs on the copies only.

| label | source | shape |
|---|---|---|
| **S** | `/tmp/ciris-native-mesh/seeded/home/data/ciris_engine.db` (Nov 8, 163 MB) | a seeded mesh: 11,269 attestations from 2,202 signers, admitted over 23.0 minutes |
| **M** | `/tmp/ciris-community-home-764742/mesh-764742-{2,24}/mesh.db` (Nov 12) | community-home runs: 24 and 25 attestations, including a removal |
| **K** | `kg_burst` (§11.1): the release lead's run, plus the 61.4.0 CHANGELOG | key_grant:epoch, 50 members × 3 devices |

None of S or M holds a single `key_grant` row, and S holds 21 blobs [T, `count(*)`]. So the key-plane rows are
priced from K and from the code, not from a store. "Rows per day" cannot be read from a 23-minute seed, so it is
given as the seed's rate. Production monthly rates are in §13.2a.

### 13.2 Per family: bytes (store S)

Bytes per row = `length(envelope) + length(scrub_signature_classical) + length(scrub_signature_pqc) +
length(additional_scrubs) +` the id and hash columns (+60 for fixed columns). The family is `attestation_type` plus
the first two segments of `dimension`.

| family (S) | rows | total bytes | mean B/row | envelope | row signature | other |
|---|---:|---:|---:|---:|---:|---:|
| `scores key:record` | 2,202 | 34.4 MB | 15,615 | 23.8 MB | 9.9 MB | 0.6 MB |
| `scores session:claim` | 4,700 | 25.0 MB | 5,322 | 2.5 MB | 21.2 MB | 1.4 MB |
| `scores identity:occurrence` | 1,137 | 15.5 MB | 13,636 | 10.1 MB | 5.1 MB | 0.3 MB |
| `delegates_to trust:accepts` | 1,683 | 8.8 MB | 5,230 | 0.7 MB | 7.6 MB | 0.5 MB |
| `delegates_to ownership:responsible_party` | 1,013 | 5.4 MB | 5,379 | 0.6 MB | 4.6 MB | 0.3 MB |
| `scores consent:community_trust` | 387 | 2.1 MB | 5,330 | 0.2 MB | 1.7 MB | 0.1 MB |
| `scores custody:ack` | 41 | 0.22 MB | 5,331 | 0.02 MB | 0.18 MB | 0.01 MB |
| `scores chat:message` | 21 | 0.22 MB | 10,303 | 0.02 MB | 0.09 MB | 0.10 MB (additional scrubs) |
| `scores consent:replication` | 34 | 0.19 MB | 5,597 | 0.03 MB | 0.15 MB | 0.01 MB |
| `supersedes chat:message` | 21 | 0.12 MB | 5,812 | 0.02 MB | 0.09 MB | 0.01 MB |

[T: SQL in the appendix, on copy S.] Those are the ten families holding the most bytes in S.

**What the split says.**

- **The row signature is about 4,500 B on every row.** That is 88 B Ed25519 plus 4,412 B ML-DSA-65, both
  base64 text [T, `avg(length(...))` on `session:claim`]. A 3,309 B ML-DSA-65 signature stored as base64 costs
  about 1.1 KB more per row than a BLOB would. Over S's 11,269 rows that is about 12 MB of the 96.8 MB
  attestation table [T, `dbstat`]. Storing it as a BLOB is a **store-side** saving (§11.4), not the kernel's.
- **Signatures inside envelopes double the cost.** A `key:record` row carries the key record, and that record
  carries its own `scrub_signature_pqc` (4,412 B), an ML-DSA public key (2,604 B) and a `registration_envelope`
  (2,788 B), all inside the row that has its own 4,500 B signature [T, `json_each` on one row].
  `identity:occurrence` likewise nests a 4,561 B signature [T]. Over S, 2,208 nested `signature_pqc` members
  [T, string count] add about 9.7 MB on top of the 50.7 MB of row signatures. **Signatures are about 68% of
  attestation bytes in S** (60.4 of 88.8 MB). CC's 59% for `key_grant:epoch` (7,641 B) is the same story.
- **The same signed fact is stored two or three times.** The 2,202 key records are rows in `federation_keys`
  (27.1 MB) **and** `key:record` attestations (34.4 MB). Occurrences are in `federation_identity_occurrences`
  (9.9 MB), `federation_identity_occurrence_history` (9.3 MB) **and** `identity:occurrence` attestations
  (15.5 MB) [T, `dbstat`]. FINAL_REFACTOR's "one row" removes that, with the typed tables becoming indexes over the
  row. It is a storage saving and the largest single one visible in S.

### 13.2a Production aggregates (canonical, 0.5.245 pre-roll backup 2026-11-10, aggregates via cirisbridge-a0)

**Source.** The canonical node's 0.5.245 pre-roll backup of 2026-11-10. These are aggregates only, produced by
`cirisbridge-a0`, with groups of n < 5 merged. I never saw a row. Eric's rule (§13.1) holds. Every figure in this
subsection and in §13.2b is this source's [T as received from the bridge via the release lead; I did not run the
queries].

**File:** `ciris_engine.db` 1,735,835,648 B, plus a 64 MiB `-wal`; no separate blob directory.
`federation_attestations`: n = 42,048, envelope bytes 275,723,212. Every signed row carries `sig_cl` 88 B and
`sig_pqc` 4,412 B (base64).

Cohort and tier are `federation` unless noted. "Months" are by `asserted_at`, as month numbers in 2026.

| rank | type / family | n | envelope total | envelope avg | months asserted | PQC sig ÷ envelope |
|---:|---|---:|---:|---:|---|---:|
| 1 | `scores` / `key` | 8,075 | 87,987,270 | 10,896 | 06–11 | 0.40 of the row (bridge) |
| 2 | `scores` / `trace` | 3,818 | 83,970,800 | 21,993 | 07–08 | 0.20 |
| 3 | `scores` / `identity` | 5,563 | 50,395,708 | 9,059 | 08–11 | 0.49 of the row (bridge) |
| 4 | `supersedes` / `trace` | 1,470 | 40,523,327 | 27,567 | 09–11 | 0.16 |
| 5 | `scores` / `capacity` | 7,293 | 4,658,347 | 639 | 08–11 | **6.9×** |
| 6 | `scores` / `consent` | 5,997 | 3,303,719 | 551 | 07–11 | **8.0×** |
| 7 | `delegates_to` / `trust` | 3,002 | 1,580,955 | 527 | 10–11 | **8.4×** |
| 8 | `delegates_to` / `ownership` | 1,316 | 849,937 | 646 | 08–11 | **6.8×** |
| 9 | `supersedes` / `consent` | 606 | 452,416 | 747 | | 5.9× |
| 10 | `delegates_to` / `self` | 727 | 431,253 | 593 | | 7.4× |
| | `supersedes` / (none) | 871 | 384,674 | 442 | | |
| | `scores` / `age_self_declared` | 932 | 360,542 | 387 | | |
| | `delegates_to` / (none) | 1,122 | 353,663 | 315 | | |
| | `consent` / `consent` | 732 | 159,362 | 218 | | |
| | `scores` / `consent` (cohort `self`) | 335 | 100,419 | 300 | | |
| | `scores` / `objection` | 7 | 62,888 | 8,984 | | |
| | `holds_bytes` | 91 | 37,219 | 409 | | |
| | `supersedes` / `capacity` | 35 | 36,945 | 1,056 | | |
| | `scores` / `hard_case` (cohort `self`, tier `local`, **unsigned**) | 19 | 24,370 | 1,283 | | |
| | `delegates_to` / `ownership` (cohort `self`) | 24 | 15,343 | | | |
| | `withdraws` | 9 | 3,704 | | | |
| | merged (n < 5) | 4 | 30,351 | | | |

The ratio column is mine (4,412 ÷ envelope avg), except where it says "bridge". The bridge's figure counts the
signature against the whole row.

**Monthly `admitted_at`** (the largest families only):

| month | |
|---|---|
| Aug | capacity 3,970 · trace 3,814 · consent 1,240 |
| Oct | key 6,611 · identity 4,808 · consent 2,497 · trust 2,001 · capacity 1,480 |
| Nov (to 11-10) | consent 1,994 · key 1,464 · trust 1,001 · identity 755 |

**What production says, against the test-shaped picture.**

1. **Today's production cost is identity, key and trace.** `key`, `trace` and `identity` scores plus `trace`
   supersedes are 262.9 MB of 275.7 MB of envelope: **95%**.
2. **On small rows the signature is the row.** Capacity, consent, trust and ownership envelopes average 527–646 B;
   the 4,412 B PQC signature beside each is 6.8–8.4× its payload. For 17,608 such rows that is about 78 MB of
   signature carrying about 10.4 MB of payload. This is where I1-style aggregation (one signature over many
   leaves, §13.5) would pay first in production. These families are per-subject acts by different signers, so the
   lever is not a wrap set. It is either a signer batching its own rows under one root (a capacity or consent
   batch), or binary signatures (S4).
3. **`admitted_at` ≠ `asserted_at`.** Keys were asserted from June but admitted from October, a re-home and
   backfill (the v59 one-way rehome, `key_plane.rs` "rehome at first open" [T]). So "rows per month" by admission
   measures migrations as much as traffic. The ledger uses both columns, and they must not be mixed.
4. **The key plane is not yet a production cost.** The canonical holds **no `key_grant` rows** and almost no
   custody rows (91 legacy `holds_bytes`). So A1-A4 (§13.4) are **future** costs that grow with rooms and family
   content; they do not explain today's file. They still rank first for the *kernel*, because they grow with use
   and they are where an item replaces N signed rows. But the bytes on disk today are the store's to fix (§13.2b).
5. **A local, unsigned `hard_case` plane exists** (19 rows, 24 KB): W6's notices, already behaving as local state.

### 13.2b The whole-file ledger (canonical, same backup, `dbstat` aggregates via the bridge)

1.74 GB = 423,788 × 4 KB pages.

| rank | what | size | share | per row | note |
|---:|---|---:|---:|---:|---|
| 1 | **trace plane**: `trace_events` 347 MB (92k rows) + its 15 indexes ~150 MB + `trace_thought_signatures` 45 MB + `trace_llm_calls` with indexes ~42 MB | **~585 MB** | **34%** | ~3.8 KB per event before indexes | the canonical reports this plane as "trace_plane dark" |
| 2 | `federation_attestations` (table + b-tree) | 507 MB | 29% | ~12 KB | 276 MB envelopes; the other ~230 MB is mostly the row signature columns (42,048 × 4,500 B ≈ 189 MB) plus ids, hashes and b-tree |
| 3 | **freelist** | **333 MB** (81,399 pages) | **19%** | n/a | free space never returned: no `auto_vacuum` / `incremental_vacuum` |
| 4 | `federation_keys` | 104 MB | 6% | ~12 KB per key (8,604) | a second copy of each key record (below) |
| 5 | `federation_identity_occurrences` + `_history` | 97 MB | 6% | (5.5k + 5.7k rows) | a second and third copy of each occurrence |
| 6 | `signed_wire_index` + 2 indexes | ~20 MB | 1% | (52k rows) | |
| 7 | `transport_destinations` | 18 MB | 1% | (18k rows) | |
| 8 | `cirisgraph_nodes` | 12 MB | 0.7% | | |
| | everything else | ~60 MB | 3% | | by difference |

**Is the PQC signature stored twice per row?** For the row's **own** signature, no. In test store S, 0 of
11,269 envelopes carry a top-level `scrub_signature_pqc` or `signature_pqc` [T, query on copy S], and
`additional_scrubs` averages 12 B [T]. The row signature lives once, in its column. **For key and occurrence
rows, yes, a different signature is stored twice.** A `key:record:v1` row carries the key record under
`key_record` (`key_plane.rs:86`) [T], and that record's own registration signature, ML-DSA public key and
registration envelope are also the columns of `federation_keys`. In S, all 2,202 of 2,202 nested
`key_record.scrub_signature_pqc` values equal the `federation_keys` row's exactly [T, join on copy S].
`identity:occurrence:v1` rows carry the signed occurrence under `identity_occurrence` (`key_plane.rs:91`) [T], and
all 1,137 of 1,137 nested signatures equal `federation_identity_occurrences.signature` [T]. In S the nested copy is
about 10.5 KB of a 10.9 KB key envelope.

Applied to production [B: extrapolated from S's shape to the canonical's averages]:

- the `key` score envelopes (avg 10,896 B, 88.0 MB) are almost entirely a copy of `federation_keys` (104 MB);
- the `identity` score envelopes (50.4 MB) are a copy of the occurrence tables (97 MB, which keep history too).

So **each signed key or occurrence fact is held two or three times, about 230-280 MB in all**, plus each
attestation row's own 4.5 KB signature on top.

### 13.2c The ranking, whole file: store first

Store-side wins come **before** the kernel's and are credited to the store (§11.4).

| order | win | layer | bytes back (canonical) | needs |
|---|---|---|---:|---|
| S1 | `VACUUM` once, then `auto_vacuum = INCREMENTAL` with a periodic `incremental_vacuum` | store | **333 MB (19%)** at once | nothing; an operational step |
| S2 | **trace-plane retention** (a plane the node reports dark; trace envelopes asserted 07–08 and supersedes 09–11) and a review of its 15 indexes | store + a CC/Server ruling on how long a node keeps trace | up to **~585 MB** of tables + **~124 MB** of trace attestation envelopes (+ their signatures) | a retention rule; trace is audit data, so this is a ruling, not a sweep |
| S3 | **one copy of each signed key/occurrence fact**: the attestation row is the record, and the typed tables become indexes over it (FINAL_REFACTOR "one row") | store | **~130-200 MB** [B] | the rehome already maps typed ↔ row (`key_plane.rs`) |
| S4 | **binary signatures** (BLOB, not base64): about 1.1 KB per signature | store | ~46 MB on attestations + ~10 MB on keys, more on nested copies [arithmetic: 42,048 × 1.1 KB; 8,604 × 1.1 KB] | a column migration (sqlite + pg) |
| S5 | **signer batches** for small rows (capacity, consent, trust, ownership: the signature is 7-8× the payload) | CC + kernel item | up to ~70 MB of the ~78 MB of signatures on those 17,608 rows, if batched | a CC row: one signer's same-family rows under one root (§13.5 shape) |
| K1-K4 | I1 set claim, I2 group KEK, I3 history grant, I4 wrap set (§13.5) | CC + kernel | **0 today** (no key_grant rows, ~no custody) → future cost | rooms and family content |

S1-S4 together return roughly **0.9-1.2 GB of 1.74 GB** [B: S2 depends on the retention ruling]. None of them is
the kernel's. The kernel's ledger is S5 and K1-K4: the costs that grow with use rather than with history.

### 13.3 Per family: time to admit (store S, an upper bound)

S records no per-row admit time. The best proxy available is the gap between consecutive `admitted_at` values in
a serial seed. That gap includes the seeder's own signing and transport, so it is an **upper bound** on admission,
not a measurement of it (gaps over 5 s excluded).

| family (S) | rows | mean gap | total |
|---|---:|---:|---:|
| `scores key:record` | 2,200 | 116.6 ms | 256.5 s |
| `scores session:claim` | 4,700 | 28.4 ms | 133.3 s |
| `delegates_to trust:accepts` | 1,683 | 37.6 ms | 63.3 s |
| `scores identity:occurrence` | 1,137 | 37.8 ms | 42.9 s |
| `delegates_to ownership:responsible_party` | 1,012 | 28.4 ms | 28.7 s |
| `scores consent:community_trust` | 387 | 28.6 ms | 11.1 s |
| `scores consent:replication` | 34 | 260.4 ms | 8.9 s |
| `scores custody:ack` | 40 | 120.1 ms | 4.8 s |
| `scores membership:acceptance` / `widening`, `chat:welcome` / `key_package` | 2-3 each | 1.1-3.2 s | 2-6 s each |

[T: window-function SQL over `julianday(admitted_at)` on copy S.] **The measurement that replaces this** is the
shadow-mode door timer (§11.1's `benches/attestation_door.rs`, run in production as a histogram per family). Its
key-grant figures are K's: 79 ms (sqlite) and 274 ms (pg) admission per row at 50 members, before 61.4.0 (§11.1).

### 13.4 Amplification: how many rows one act makes this node sign or store

| # | causing act | rows per act | bytes per act | CC's hypothesis | verdict |
|---|---|---|---|---|---|
| A1 | **custody re-ack**: a device holding B blobs | B signed rows **per day**, for ever (`HOLDING_CLAIM_REACK_AFTER_SECS` = 24 h, `holding_claim.rs:634`) [T] | B × 5.3 KB per day (custody:ack mean 5,331 B in S [T]); B = 10,000 gives ~53 MB/day per device, replicated to the cohort | (d) "one row per holder per blob?" | **Confirmed, and worse.** One row per holder per blob, `evidence_refs` "exactly one entry" (`custody_ack.rs` doc) [T], **re-signed daily**. The pass is capped at 256 claims (`HOLDING_CLAIM_REACK_MAX_PER_PASS`, `:662`), which the doc sizes as keeping "about 12,000 claims live" [T]. **A device holding more blobs than that cannot keep all its claims live**: a hard ceiling, not just a cost |
| A2 | **sealed write at `self`/`family`** | one `key_grant:content` row per recipient occurrence: Σ members' live devices (CC 4.4.3.4.1; "fresh per write, O(members) wraps", `community_dek.rs` doc table) [T] | 5 members × 3 devices = 15 rows × ~7.6 KB ≈ **115 KB for 200 B of content** (about 575×) | (a) ~100 KB | **Confirmed** [T on the row count; the row size is B, taken from K's 7,641 B epoch row, because no store holds a content row] |
| A3 | **family join** (a newcomer with D devices) | O(H) × D, where H = the family blobs in the group's history: `rekey_for_newcomers` unwraps each blob's DEK and wraps it once per newcomer device (`at_rest_cascade.rs:1534-1573`) [T]; CC 3.3.4 item 3 makes each wrap a `key_grant:content` row [T] | H = 1,000, D = 3: 3,000 rows ≈ 23 MB, and ≥ 3,000 × (0.2 + 1.3 + 0.3) ms ≈ **5.4 s of floor** | (b) O(history) × devices | **Confirmed** [T on the walk; B on the H and D values] |
| A4 | **removal, or the seat, at the community epoch** | members × devices **per minter** (epochs are `(community, minter, epoch)`, `store/sqlite.rs:9654-9670`) [T] | K: 150 rows, 1.15 MB per minter at 50 × 3 (lead's run; 150 rows [T] in the 61.4.0 CHANGELOG). With M active minters: M × 1.15 MB, e.g. 11.5 MB for M = 10 | (c) minters × devices | **Confirmed** |
| A5 | **one key registration / one occurrence** | 1 typed row + 1 attestation (+ the occurrence history row) | key: 12.3 KB in `federation_keys` + 15.6 KB as `key:record`; occurrence: ~8.7 + 8.2 + 13.6 KB [T, S `dbstat` ÷ rows] | not in CC's list | **added**: a 2-3× storage copy of every signed fact in its family |
| A6 | **the 15 `hard_case` kinds** | one row per node per event | 1,723 B for 2 rows in M [T] | (e) if they stay signed | **Mostly moot after W6**: they become notices, except the CC 3.4.13 safeguarding escalation and the tombstone. Small in M, but per node and replicated, so it would scale with N nodes × events had it stayed |

**Production check (§13.2a):** the canonical holds no `key_grant` rows and only 91 legacy `holds_bytes` rows, so
A1-A4 are not yet a production cost. They are what grows as rooms and family content grow.

Ranking by what they would cost a live node: **A1** (unbounded in held blobs, daily, with a ceiling), **A2** (every sealed
write), **A3** (every join, in history), **A4** (every removal, in minters), **A5** (every key and occurrence, in
storage).

### 13.5 Multi-row items for the top five

The common shape: **one signature over a root, and leaves that each carry an inclusion proof.** A leaf is checkable
on its own once the root's signature is held, so a recipient can be sent the header plus its own leaf and nothing
else.

| # | replaces | item | bytes | admit cost | kernel fold |
|---|---|---|---|---|---|
| **I1** (A1) | B per-blob custody rows per device per day | **set claim**: one signed row per device per scope per day, `{ root = Merkle(sorted blob digests), count, bytes, prev_root }` with the digest list (32 B per blob) or a daily **delta** (added/removed) chained by `prev_root` | 10,000 blobs: 4.5 KB signature + 320 KB list (or a delta of a few KB) against ~53 MB | one sign, one verify; the leaves become index entries, not rows | **ONE item.** `touches` = `{Content(d)}` for each listed digest; `pick=chain(prev_root)` (CC already has `chain` picks [T]). "Who holds X" is a probe of persist's index. It also removes A1's 12,000 ceiling |
| **I2** (A2) | R `key_grant:content` rows per write | **group key-wrapping key (KEK)**, as the community epoch already does ("one shared per `(community, epoch)`… O(1) per emission", `community_dek.rs` doc table [T]): each member device holds the group KEK of the epoch through one grant per device per epoch; a write wraps its DEK once to the KEK, **inside the content row**, and signs no `key_grant` row at all | 15 rows / 115 KB per write → ~60 B per write, plus 15 rows once per epoch | no extra sign per write | **ONE item** (the content row). Read set `{Roster(group), Keys(member devices)}` for the epoch grants |
| **I3** (A3) | O(H) × D rows per join | **history grant**: the newcomer device gets one wrap of a **history key** that wraps the group's past epoch KEKs (or the epoch chain), and not one wrap per blob | 3,000 rows / 23 MB → D rows (~23 KB) | D signs | **ONE item per device**: a draft of one row, read set `{Roster(group)}`. The O(H) walk leaves the hot path |
| **I4** (A4) | members × devices rows per minter per removal | **sign-once wrap set**: header (DEK id, epoch, minter, group) + per-device wrap leaves + one root signature; each leaf ships to its recipient with its path (log₂ 150 ≈ 8 × 32 B) | 150 rows / 1.15 MB → 4.5 KB + 150 × ~1.5 KB ≈ 230 KB (~80% fewer; CC estimated ~60%) [B: the leaf size assumes 1,088 B of ML-KEM-768 ciphertext + 32 B X25519 + AEAD of the DEK, base64] | one sign per removal per minter instead of 150 | **ONE item with per-leaf verdicts** (`Answer<Vec<LeafVerdict>>`), read set `{Roster(group), Keys(recipients)}`. **Constraint:** CC rc7 retired the key-grant *set* carrier (`KeyGrantRefusalReason::SetRetired`, `key_grant.rs:17-18`, `:305`) [T]. A wrap set returns only if CC re-admits it in this per-leaf-addressable form. W19 asks |
| **I5** (A5) | 2-3 stored copies per key or occurrence | **one row, typed tables as indexes** (FINAL_REFACTOR §4) | ~50% of key and occurrence bytes in S | unchanged | no item needed; a storage change |

**Why self/family do not already use a KEK, and what forward secrecy would then cost.** Self/family chose a fresh
DEK per write, so forward secrecy on removal is free: "the per-write fresh DEK means future writes simply exclude
them" (`at_rest_cascade.rs` `rekey_for_newcomers` doc) [T]. The price is A2 on every write and A3 on every join.
With a KEK, removal costs one rotation: a new epoch KEK wrapped to the remaining devices (members' devices minus
one member's, about 12-15 rows for a 5 × 3 family) **once per removal**, instead of 15 rows on every write.
**Device revocation must rotate too.** `formal/key_plane` found exactly this gap at the epoch tier: a revoked device
of a member who stays kept the epoch key until the next rotation (K8, C558) [T]. So the rule is rotate on member
removal **or** device revocation (K6 already names "a rotation falling due"). For a family that writes more often
than it loses members or devices (the normal case), the KEK wins by the write/removal ratio.

**CC's ruling on the KEK and the history key (DERIVED, rc19).** For self/family **files**: yes, a group key,
rotating on member removal **and** device revocation, with **one history key** for a newcomer instead of the
walk (I2 + I3). Edge confirmed in code that the per-recipient grant is paid on self and family **file** writes,
not on chat or community. CC will model it in `formal/key_plane` before the text moves. **Signer batching (S5) is
the same set object (§13.6a), not a new family.**

**Can the kernel fold each as ONE item?** Yes, for all four items, under one rule. An item is folded as one held
row when its leaves share **one signer, one signed instant and one family**, and each leaf is checkable against the
signed root. `touches(item)` is the union of its leaves' keys, and the verdict is per leaf. Persist explodes leaves
into **index entries** (for "who holds X", "which wraps name this device"), never into rows. A leaf that needs its
own signer, or its own instant, is a row, not a leaf.

### 13.6 Multi-row items against the breakers

A leaf that is admissible only once its header is held is B4 (missing parent) again. The rules that keep items
order-free:

1. **Never drop a leaf or a header.** A leaf whose root is not held is held `Inert { missing: header(root id),
   retry: WhenAny(Refs(root id)) }` (§5.3), so the header's arrival re-evaluates exactly those leaves through the
   read-set index. A header whose leaves are missing is a held item whose view says what is missing.
2. **Completeness is a view, not a gate.** With inclusion proofs, a leaf needs only `{header, itself}`, never the
   whole set, so no item is all-or-nothing, and a recipient that was sent only its own leaf is complete *for it*.
   An item that needs every leaf (a set claim's count against its list) reports `incomplete { have, of }`, and
   nothing waits on it.
3. **Two headers, one item id** (a fork, or a resend with a different root): both are held, the item's view is
   `forked`, and its leaves are inert, as with peer records (B11). Never first-header-wins.
4. **A chained item** (set-claim deltas): a delta before its predecessor is held and inert on `Refs(prev_root)`,
   and the head is `pick=chain`, as for group heads (B12).
5. **Transport ships items, routing ships leaves.** `route(item leaf, Peer)` (§5.9) decides per leaf; Edge batches
   the header with the leaves it sends. Persist's settle (`settle_if_held`) settles at the leaf: a re-sent leaf
   whose root is held is idempotent success.

### 13.6a The set object: CC's five conditions (DERIVED, rc19 `6453665`)

A set object is admitted **only as an encoding of rows**, under five conditions. Each one maps to a kernel check:

| condition | kernel check |
|---|---|
| **flat**: no set holds a set | a leaf's family may not be a set family; a load-time and parse-time check |
| **enumerated**: it lists its leaves, never "all who…" | the leaf list is explicit; the audience is the kernel's to compute (`audience`, §5.9), never the item's to state |
| **one signer, one signed instant, one family** | the header carries all three; a leaf naming another is malformed |
| **leaf verdicts independent of siblings** | per-leaf `Verdict`; a headerless leaf is held `Inert`, waiting with a lapse (§5.9a); two headers make the item `forked`, and both are held (§13.6 rules 1-3) |
| **THE LAW: the fold over the set equals the fold over its leaves as separate rows** | this is the **admission test for every proposed item**: harness 6 in §6.2 below. It is the merge law (§4.1 #1) applied to encodings: an item is admissible iff exploding it changes no digest |

**Chained items** (`prev_root`, e.g. set-claim deltas) are allowed with a bound: a **full claim at a stated
interval**, so no fold walks an unbounded chain. For I1 that is a full set claim at least every W (72 h, the
custody freshness already in force, `CUSTODY_LIVE_SECS` [T]), with daily deltas between. The fold reads the last
full claim plus at most `interval / delta period` deltas (3 for I1).

**Harness 6 (added to §6.2's list): set-encoding equivalence.** For every set family and generated item, the
digest of `fold(held ∪ {item})` equals the digest of `fold(held ∪ leaves(item))` under every shuffle, and with any
proper subset of leaves (the headerless and partial cases). A family that fails it is not a set family.

### 13.7 What to optimise first

The whole-file order is §13.2c: the store first (S1 vacuum, S2 trace retention, S3 one copy, S4 binary
signatures), then S5 signer batches, then the kernel's items. Within the kernel's own ledger, ranked by growth
with use (production holds none of these yet, §13.2a point 4):

| order | change | layer | expected effect (test-shaped) |
|---|---|---|---|
| 1 | I1 set claim | CC row + kernel item | removes A1's daily B-row cost and its 12,000-claim ceiling |
| 2 | I2 group KEK for self/family, rotating on removal **and** device revocation | CC ruling (CC 4.4.3.4.1) + store | removes A2: about 115 KB → 60 B per sealed write in a 5 × 3 family |
| 3 | I3 history grant | CC + store | A3 from O(H) × D rows to D rows |
| 4 | I4 sign-once wrap set | CC re-admission (W19) + kernel | A4 ~80% fewer bytes per minter per removal |

### 13.8 The secret ranked poll: a cell layout for CC 6.1.9 (persist's proposal)

**What CC fixes** (rc19, read [T]):

- CC 4.5.13: "A node keeps a tally of how many ballots carry each ranking, and finishes the count from that tally
  alone… A secret poll (CC 6.1.9) carries one cell for each ranking, and its composite is that same tally."
- CC 6.1.9: a member's community cell is a one-hot "over the poll's options plus *none*", split into two
  additive shares over a prime field with a one-hot validity proof (Prio3 histogram). It is sealed under the
  community's epoch key and sent as `census:member:share:v1` to two tally members drawn by
  `H(group_exporter_secret ‖ period)`. The result is `ballot:tally:{poll_id}:v1`, which every member recomputes.
  Every eligible member emits its cell every period "at the fixed size, whether or not a poll is open".

What persist shapes is the **layout**: how a ranking becomes a cell, how cells stay secret, how tallies merge,
and what it costs.

**1. The domain: one cell per ranking, plus none.** For k options and r ranks (r = 3 unless the poll declares
otherwise), a ballot is a sequence of 1..r distinct options. The cell count is

```
L(k, r) = 1 (none) + Σ_{j=1..min(r,k)} k! / (k−j)!        r = 3:  1 + k + k(k−1) + k(k−1)(k−2)
```

A one-hot over this domain makes an invalid ballot (a repeated option, more than r ranks, two rankings at once)
**unrepresentable**: the validity proof ("every entry 0 or 1, the entries summing to 1") already admits exactly
one ranking or none. No extra ballot check is needed.

Why not r one-hots of k + 1 cells, one per rank position (27 cells at k = 8, not 401)? Because they lose the joint
ranking. Instant runoff transfers a ballot to its *next standing* choice, which needs the whole ranking. CC's one
cell per ranking is the smallest summary from which the count finishes.

**2. Addressing: by stable id, never by position** (Holon's "join by stable id, never by array index", §4.1).

- **Options are named, not numbered.** The poll record (sealed, signed, carrying `poll_id`) lists its options as
  `option_id = H("ciris/poll-option/v1" ‖ poll_id ‖ canonical option body)`, plus the **declared order** used
  only for the tie-break (CC 4.5.13: "goes against the option later in the choice's declared order").
- **A cell's id is its ranking:** `cell_id = H("ciris/poll-cell/v1" ‖ poll_id ‖ j ‖ option_id_1 ‖ … ‖
  option_id_j)`, and `none` is `H("ciris/poll-cell/v1" ‖ poll_id ‖ 0)`.
- **The vector position is derived, never stored.** The Prio3 vector needs positions. They come from a canonical
  enumeration fixed by the poll record: rankings ordered by length, then lexicographically by option id **as
  sorted by id** (not by declared order). The position of a ranking is its rank in that enumeration, computed by
  the factorial-base formula. Positions exist only inside a share vector. Every row that leaves the tally
  members (partials, composite, tally) carries counts keyed by `cell_id`, or a dense vector together with the
  enumeration's digest `H(sorted option ids ‖ r)`, so a reader re-derives the mapping and never trusts an index.
- **A changed option set is a different poll.** Positions are a function of the option set, so amending the
  options mints a new `poll_id`; nothing is re-indexed in place.

**3. Secrecy until the tally.** Unchanged from CC 6.1.9, applied to the ranking domain:

- The member's node encodes its ranking as the one-hot of length L(k, r), splits it into two additive shares
  over the field, and seals each share, with its share of the validity proof, under the community epoch key, in a
  `census:member:share:v1` addressed to one tally member (`for_key_id`).
- Neither tally member sees a vector. Each sums the shares it accepts into a **partial** keyed by `cell_id`,
  deletes the shares, and publishes `census:member:partial:v1`. `ballot:tally:{poll_id}:v1` is
  `partial_a + partial_b` element-wise, and every member recomputes it.
- **Fixed size.** The field a poll fills must be the same size in every period of a community, whether or not a
  poll is open (it may differ between communities, which reveals only their declared `poll_k_max`). So the community record declares `poll_k_max` (and r), and the poll field is always
  L(k_max, r) cells. A smaller poll uses the k_max enumeration with its k options (sorted by id) in
  the first k slots and k_max − k **phantom** slots that no ballot may rank. The rankings that touch a phantom
  slot are valid one-hot space that stays zero.
  Without a declared k_max, the field size would reveal k.

**4. A composite is the merge of per-cell counts.** Tallies are maps `cell_id → u64` that merge by adding per key
(§4.3). The partials, the composite and the tally of the whole are the same monoid: `tally(A ∪ B) = tally(A) +
tally(B)`, whatever the order. The finish (instant runoff) reads only the merged tally, in whole numbers, in fewer
rounds than there are options.

**5. Byte cost per member per period** (r = 3). The share field is assumed to be Field128 (16 B), the helper's
measurement share is a 32 B seed, and the proof share is about 2·⌈√L⌉ field elements. **Those are [B]**: the
Prio3 parameters are whatever CC's registered `aggregation_algorithm_id` names, and the numbers move with it.

| k | cells L | leader share | helper share | proof share (≈) | tally / composite (dense, 16 B/cell) | two share rows: leader (share + proof) + helper (seed + proof) + 2 × 4,500 B signatures |
|---:|---:|---:|---:|---:|---:|---:|
| 3 | 16 | 256 B | 32 B | 128 B | 256 B | ~9.5 KB |
| 4 | 41 | 656 B | 32 B | 224 B | 656 B | ~10.1 KB |
| 5 | 86 | 1,376 B | 32 B | 320 B | 1,376 B | ~11.0 KB |
| 6 | 157 | 2,512 B | 32 B | 416 B | 2,512 B | ~12.4 KB |
| 7 | 260 | 4,160 B | 32 B | 544 B | 4,160 B | ~14.3 KB |
| 8 | 401 | 6,416 B | 32 B | 672 B | 6,416 B | ~16.8 KB |

[cells T by the formula; the byte columns are arithmetic on the assumptions above.] **What the table says:**

- The two hybrid signatures are most of the cost at every k up to 8: 81% at k = 5, still 54% at k = 8 (§13's
  finding again). Sealing overhead is not counted.
- Because every member pays the k_max size every period, `poll_k_max` is a cost the community chooses. k_max = 8
  costs each member ~16.8 KB per period for a field that is padding when no poll is open, against ~9.5 KB at k_max = 3.
- A sparse tally (only nonzero cells, 32 B id + 8 B count each) is smaller than dense once fewer than ~40% of the
  cells are used. That is likely at k = 8 with few voters, so the published tally should be sparse; the shares
  cannot be, because their size must not depend on the ballot.

**6. Open for CC.**

- **The k-floor against small cells.** CC 6.1.9 withholds a cell under k = 10 owners. A ranking histogram at
  k = 8 has 401 cells, and most will be small, but instant runoff cannot finish from a tally with cells
  withheld. Persist sees two options. (a) The floor applies to the poll's `source_count` only, and the full
  ranking histogram is published, which is secrecy against tally members but not against small-cell inference.
  (b) The two tally members also compute the runoff jointly and publish only the per-round standing totals
  (each a sum over cells, so more of them clear the floor) and the result. That costs every member the ability to
  recompute the rounds from cells. CC should rule.
- **One ballot per person (`pick=agree`).** Census counts owners, not nodes, and one accepted cell per owner per
  period. A poll open over several periods needs a rule for which period's cell counts. Persist proposes **the
  closing period's composite only**, with members re-emitting their ballot each period while the poll is open.
  That keeps one cell per owner without linking per-period tokens.

---

## Appendix: how the counts were taken

| count | command or read |
|---|---|
| 180 `check_*` | `grep -rhoE 'pub (async )?fn check_[a-z_]+' src/federation/*.rs` (invariant files excluded) `\| sort -u \| wc -l` |
| 57 gate calls in `plan_put_attestation` | `awk` lines 654-1517 of `attestation_admit.rs`, grep `::(check\|verify\|resolve\|validate)_*` |
| 119 invariant files, 34 tests | `ls src/federation/*_invariants.rs \| wc -l`; `ls tests \| wc -l` |
| 22 rewriting sqlite migrations | `grep -l '^\s*UPDATE\|^\s*DELETE FROM' migrations/sqlite/*/*.sql \| wc -l` |
| 20 `record_hard_case` calls | grep across `src`, excluding the definitions; includes calls inside `#[cfg(test)]` in `store/*` [B: the count of production sites is lower] |
| CC transitions, guards, sources | Python over `transitions.json` rows: sum of `transitions`, count of non-empty `guard.value`, Counter over each cell's `source` |
| 8 refusing `no` guards | regex over guard strings for a leading `no ` or ` no ` |
| fold, count, placement, freshness coverage | `family_model.json` `_meta.coverage` and a Counter over row cells |
| reactions | `reactions.json` `_meta` and a Counter over `effects[].effect` |
| guard words (`one` 30, `each` 11, `not` 9, `no` 8, `set` 2, `all` 1) | `re.findall(r'\b(one\|no\|each\|set\|all\|not)\b(?= \|\()', guard)` over every guard string. Nested `one` clauses inside `each(...)` count, so 30 exceeds CC's 25 |
| fold classes (`over` 17, `cut` 11, pick max 15 / rank 8 / chain 4 / once 4 …, combine median 5 / sum 2 / min 2 / max 1) | regexes `pick=([^;]*)`, `combine=(\w+)`, `\bcut=`, `\bover=` over `family_model.json` fold cells. A pick naming both `rank(` and `max(` was classed max, so max is 15 against CC's 13 |
| reactions with `unless` (10) | `sum(1 for r in reactions if r.get('unless'))` |
| §13 bytes per family (store S) | on the copy: `select attestation_type, dimension-prefix, count(*), sum(length(attestation_envelope) + length(scrub_signature_classical) + length(scrub_signature_pqc) + length(additional_scrubs) + id/hash column lengths + 60) … group by family order by total desc` |
| §13 table sizes | `select name, sum(pgsize) from dbstat group by name` |
| §13 nested signatures | `(sum(length(env)) − sum(length(replace(env,'signature_pqc',''))))/13` over all rows: 2,208 |
| §13 admit-time proxy | `julianday(substr(admitted_at,1,23))·86 400 000 − lag(...) over (order by admitted_at)`, grouped by family, gaps < 5 s |
| persist vendors no `transitions.json`, `reactions.json` or `family_model.json` | `find . -name …` (target excluded): no hits [T] |
