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
| **out** | views (what is true now, and why); the queue (transitions whose `from` matches the view and whose roles the standing meets); effects (stop serving, destroy bytes, wrap a key, raise a report); drafts (rows the node itself must sign) |
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
| B1 | a, k | owner binding: `admission.rs:13091` [T]; C557 | a new owner's binding that arrives ahead of the old owner's withdrawal is lost; two nodes read different owners (`formal/owner_binding` O6) | hold both. `owner_of` = the unique live cosigned binding, else none. This is the model's `fold/unowned` reading, which gives up O4. CC rules O4 against O7 (§10 W1) |
| B2 | a, f | `withdraws` stamp: `attestation_admit.rs:1163-1181`, `precedence.rs:258-280` [T] | entitlement depends on whether the target was held at the `withdraws`'s arrival | entitlement is a fold over (target, `withdraws`, the signer's standing at the `withdraws`'s signed instant); the stamp column is deleted. The release lead confirmed this independently (`attestation_admit.rs:1170-1181`, TESTED by them): the same rows in a different arrival order give a different retraction verdict, on the retraction path Edge reads. It is C557's class |
| B3 | a | delegation cycle `admission.rs:18517` [T] | the edge that closes a cycle depends on order | the cycle is a view; its closing edge is chosen by `max(asserted_at), max(id)` and is inert. Same on every node |
| B4 | a, i | gates 5, 11, 12, 14, 15 in §2.2 [T] | a row that arrives before its key record, consent, standing or subject is dropped; the peer may never re-offer it | **no gate drops.** The row is held with verdict `Inert { reason, retry: WhenAny(keys) }`. When a key in `retry` changes, its verdict is recomputed for free through the read-set index (§5.4). This is `formal/owner_binding`'s `again` reading applied to every door |
| B5 | c, a, k | W at receipt: `self_roster.rs:556-575`, `key_grant.rs:1197-1210`, `admission.rs:13032`, `admission.rs:5301` [T] | "a signer stands at its signed instant; past W it must also stand **at receipt**." Standing at receipt is the held set at receipt, so an eviction that arrives after the row admits it on one node and refuses it on another, for good | judge standing at the row's signed instant over **all** rows held, ordering the eviction by its own signed instant. Use W only as `first_held − asserted_at ≤ W`, which is a function of the row and its first-held instant. Needs CC's ruling on #1049 (§10 W4) |
| B6 | a, c, e | cosign hold: `cosign.rs:853`, `:1199`, V214 partial UNIQUE [T, doc] | expiry deletes held rows on a sweep; one open proposal per proposer refuses the second | pending, assembled and lapsed are views over held `cosign:*` rows; the reaction `drop_held` (`reactions.json` [T]) becomes the view `lapsed` plus an optional storage reap (§3.1) |
| B7 | e, c | community DEK epoch: `store/sqlite.rs:9654-9684`, `community_dek.rs:557-575` [T] | a mutable counter; it rotates when a signed `removed_at` exceeds a **local** `minted_at`; bumping twice for one removal gives two epochs [B] | epoch identity = `H(community, minter, the departure rows since the previous epoch)`. Rotation is due when the held departure set grows (`formal/key_plane` K6: "the epoch changes only after a departure or a rotation falling due" [T]). The minted DEK is still persist's secret |
| B8 | c | takedown `content_binding` `takedown_tombstone.rs:602-611` [T] | the subject set is read against `Utc::now()` | read at the notice's first-held instant |
| B9 | b | destroy bytes and destroy keys: `takedown_tombstone.rs:913`, `engine.rs:9415`, `community_dek.rs:1160-1170` [T] | final; under a later rule version the view could say "served" | `Effect` with a deterministic id, acknowledged by a local `purged` row (§1). Under a new rule version a refold that would not have destroyed raises `Notice::EffectNoLongerJustified`, never an undo |
| B10 | d | latest-wins upserts `store/sqlite.rs:25536`, `:25735`, `:26695` [T] | the loser row is gone; a tie keeps the first | hold every row; `pick=max(asserted_at), min(id)` |
| B11 | h | peer record TOFU `directory_admit.rs:155-176` [T] | the first pubkey for a key id wins | hold both; the view reads `conflict` and serves neither (the same law as O8, "a reader that holds two reads none") |
| B12 | h, a | group head supersede `group_supersede_admit.rs:77-100` [T] | a successor that arrives early is refused; of two forks, the first wins | a fold over the `prev_head_digest` chain; a fork is a view; the head is `pick` over the unforked tip |
| B13 | c, e | accord `created_at` `accord_admit.rs:93-95` [T] | a local instant enters the record | the serve cursor stays persist's and no verdict reads it [B: confirm no fold reads `created_at`] |
| B14 | f | `hard_case` emissions, 20 call sites [T] | a node writes its own fold result as a signed row; peers replicate this node's opinion | a notice (FINAL_REFACTOR §5.6). Rows remain only for CC-listed signed acts |
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
| 3 | **Integers only; refuse on overflow** | `holon-scene/src/lib.rs:19-20`: "Integers only. No float appears in this crate, so a native build and a wasm build agree bit for bit by construction" [T]. `holon/src/ledger.rs:11-17`: the ring "REFUSES (panics) on overflow rather than wrapping" [T] | scores, weights and thresholds are exact: integer fixed-point or a rational `(num, den)` in `u64`/`i128`, using checked arithmetic. Overflow is a **verdict** (`Unserved { cell }` with an overflow reason), never a panic and never a wrap, because a kernel must not abort a node. This is also CC's open COSE float gap (§10 W16). Persist carries floats into verdicts today. `Attestation.weight` is `Option<f64>` (`types.rs:1645`) [T], and the weighted-rubric arm of `consensus::evaluate` sums `f64` weights (`consensus.rs:38`, `:418`, `:436`) [T]. An `f64` sum is order-dependent past exactness, which is Holon's `RentLedger` warning (§4). CC#203 drops `weighted:{rubric}` (FINAL_REFACTOR §5.8), and that removes this arm |
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
pub enum Retry { Never, WhenAny(KeySet), At(Micros) }
// Holon's four values (§4.1 #7): Live = Pass, Inert = Fail (with the curing row), a policy Branch rides in
// Live.to (enacted | cancelled | lapsed), Unserved = Void. Overflow in any count is Unserved, never a wrap.
pub struct Missing { pub roles: SmallVec<Role>, pub voices: Option<(u32, u32)>, pub rows: SmallVec<Need> }
```

`Token` is the public refusal contract (FINAL_REFACTOR §5.6). Today's tokens are kept byte for byte, so
`federation_*` kinds and Python types do not move in a mechanical step. `Retry::Never` is terminal and the rest
are retryable, which is what Edge's retry schedule reads.

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

So the fixpoint is reached in at most `depth(emit graph)` rounds. Today that is 1 [B: no emitted family in
`reactions.json` is itself an `on` trigger of an `emit`; I checked the effect list, not the closure]. Persist
asserts the bound per batch.

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

### 5.9 Placement: what persist may refuse to hold

Persist keeps one non-kernel refusal: **may I hold this at all**. It covers the quota, "never store what we are
not party to", and the audience. If placement depends on held rows (am I in this room?), it is order-dependent
again. So placement is also a kernel answer, with three outcomes:

```rust
pub enum Placement { Hold, Park { until: KeySet }, Discard }   // Discard only for Retry::Never reasons
```

`Park` is a bounded inbox (persist's quota) re-offered when a key in `until` changes. CC's `placement` column
is a gap for 156 of 184 families [T, `_meta.coverage.placement`], so today almost every family takes the
default (§10 W8).

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

There are five harnesses. They are named here and not built.

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
   identity (Holon's "plant is vacuous" check, §4.1 #5).
4. **Commuting square.** For generated `(S, r)`: `cached_answer(S) ⊕ invalidate(touches(r))` against
   `fresh_answer(S ∪ {r})`. This is the certificate the answer cache must hold (§5.4).
5. **Planted mutations.** `KernelMutation` (§4.1 #8). The must-convict set has to move a digest or fail a vector:
   `DropOnRefuse`, `StampAtDoor`, `LastProcessedWarmStart` (a cache that remembers its last update), and
   `MissingInvalidationEdge` (drop a `Slot` key from `reads`). The must-not-move set has to leave every digest
   equal: `ReverseInput`, `ShardFolds`, `ColdCache`. Only the two halves together are evidence.

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
| W1 | **C557 owner binding** | `formal/owner_binding`: no reading holds O4 and O7 together [T] | rule it. The kernel can implement `fold/unowned` (gives up O4) or `again/unowned` (gives up O7, needs Park). Persist recommends `fold/unowned`: it is the only reading without a dropped row |
| W2 | **uniqueness guards that refuse** | 8 `no X@admitted … else refuse` clauses in 5 families [T] | a `tie_break` cell for each (CC#203), so the duplicate is held and inert |
| W3 | **guards** | 26 of 459 transitions typed; 433 `generic` [T] | type the 21 non-set-function sites in §2.2 first: 5-7, 9, 11, 12, 14, 15, 19-24, 26-30, 33, 34. Each names a persist anchor to read |
| W4 | **W at receipt (#1049)** | `freshness`: 174 `generic`, 7 prose, 3 gap [T]; persist judges standing at receipt in 4 places [T] | rule that W is `first_held − asserted_at ≤ W` (row-local) and that standing is judged at the signed instant over all held rows. Otherwise W stays order-dependent by construction |
| W5 | **folds and counts** | fold: 76 `cc-table`, 108 `generic`; count: 16 `cc-table`, 164 `generic`, 4 `gap` [T] | type the folds the kernel needs first: `owner_of`, epoch identity (W7), group head chain, cosign pending/assembled/lapsed, peer record conflict |
| W6 | **emit or notice** | 25 emits, including 15 `hard_case:*` [T, effect counter]; 7 `not_yet_by_origin_door` [T] | mark each emit as a signed act (row) or a node's computation (notice, FINAL_REFACTOR §5.6). Persist expects only `key_grant:*`, `consent:state:expired` and `consent:decay:*` to remain rows |
| W7 | **epoch identity** | `formal/key_plane` K6 states when an epoch changes, not what names it [T] | name an epoch by the digest of its departure rows, not a counter |
| W8 | **placement** | 156 of 184 `gap` [T] | a placement cell so `Hold / Park / Discard` (§5.9) is a table read |
| W9 | **operator settings in verdicts** | `withdraws_depth` (V157) [T] | a governance-policy number, or delete the dependence |
| W10 | **effect vocabulary** | `do` acts: `cancel_watch`, `cease_replication`, `deregister_peer`, `drop_held`, `stop_serving`, `destroy_bytes` [T] | mark each `irreversible` or `idempotent`; recast `stop_serving` and `drop_held` as views; add `destroy_key` (crypto-shred), which persist does on a sweep today (`community_dek.rs:1137` [T]) with no reaction naming it |
| W11 | **acknowledgement row** | `purged` and `sealed` are new event words [T] | bless `purged` (local tier, `refs=[effect id]`) as the acknowledgement of an irreversible effect (§1) |
| W12 | **clock guards** | `within(accord_halt)` and `after(moderator_election)` [T] | say which instant each reads (first-held of which row) |
| W13 | **the ruled column** | roles 146 / policy 146 `code-v61`; signer_rule 122, subject_rule 164, cosign_rule 169, lifecycle 181 `code-v61`; undo 30 `gap`; roles 2 `gap` [T] | as FINAL_REFACTOR §5.5: each `code-v61` cell is step 1 (state today). The differential gives step 2 for free |
| W14 | **reader trust set** | 32 folds `by=reader` [T] | specify the input: reader key and accepted roots, or the reader's own trust rows |
| W15 | **CEWP tables** | rc17, no guards, no reactions [T] | one tag for both kernels (§7) |
| W16 | **exact numbers (COSE float gap)** | `weight: Option<f64>` (`types.rs:1645`) and f64 rubric sums (`consensus.rs:418`) [T] | type every score, weight and threshold as an integer fixed-point or a rational on the wire, so the kernel never sees a float (§4.1 #3) |
| W17 | **cost classes** | none published | per-transition and per-fold `CostClass` via `tools/kernel_cost.py`; the build refuses a mismatch (§11.2) |
| W18 | **the census-family guards still refuse** | `census:*` folds already carry `pick=once(…)` tie-breaks [T, fold cells], but their guards still say `no … else refuse` (B18) [T] | make the guard defer to the fold's `once` tie-break, so the table stops stating the rule twice |

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

**Holding the implementation to it.** Every compiled rule cell carries its `CostClass`. CC will publish
per-transition classes through `tools/kernel_cost.py`, and the build refuses a table whose class differs from the
kernel's own classification. Each class has a bench, so the budget is enforced per class:

```rust
pub enum CostClass { Probe, NonMonotoneProbe, Linear { over: SlotId }, Join, OrderStat, Wake }
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
| persist vendors no `transitions.json`, `reactions.json` or `family_model.json` | `find . -name …` (target excluded): no hits [T] |
