# The final refactor: one row, one model, one engine

Status: DRAFT in review. CC ruled the spec questions at rc17 `6dc2091` and `4794d9f` (CIRISPersist#1205,
comments 6670437725, 6670504193) and confirmed the §8.3 placement. Agent and Server censuses are in.
Eric has ruled §16 items 1, 4, 6, 7 and 15. Edge and Verify are outstanding; Verify is down until Eric brings it
up before v62 starts. Nothing here is built.

Issues: CIRISPersist#1130, #1205, #934 (residual), #681, #679, #1004, #1174,
#1185. Spec: CC 2.6.1.8, CC 4.5.13, CC#189 (`manifests/family_model.json`). Measured
at v61.0.3 (`7894b39c`). Read with CEWP: https://cirisai.github.io/CEWP/.

This document supersedes the layer description in
`FSD/PLATFORM_ARCHITECTURE.md` §2 and §5.1. No other FSD states the target
architecture.

## 0. The thesis

CEWP states the fault: "Every app keeps its rules twice: in the code that draws the
buttons and in the code that refuses the request. They drift, and the drift is where
authorization bugs live." Persist keeps its rules many times over. Every number in §1
points at that one fault, and this refactor makes each fact stated once.

Persist has three jobs, in CEWP's placement: an append-only verifiable store, a
registration policy that decides what may be logged, and an authorization walk ("the
union of immudb, a SCITT transparency service [...] and SpiceDB"). Everything here serves
those three jobs, plus a fourth the census surfaced: a local operational store for the host
(§8.2). The refactor does not shrink that fourth job, and it does not let it into the first three.

| one | replaces | section |
|---|---|---|
| one row view | 375 raw envelope reads, two signed forms | §4 |
| one family model, one predicate | 96 `check_*` gates, 8 rule tables, an 880-line hand sequence; the door and the queue as one rule | §5 |
| one answer per question | 15+ retraction deciders, 4 threshold layers, literal windows | §6 |
| one plan/execute boundary and dialect engine | decisions in backends, 498 paired functions | §7 |
| one narrow surface | a concept crossing five layers, 890 dispatch arms, 735 Python functions | §8 |
| one schema truth | two replayed DDL models, 394 migration files on a new install | §9 |

## 1. What we measured

Evidence marks used throughout: **M** measured at the tag, **T** tested by a real
run recorded on a ticket or in project history, **B** believed. Appendix A gives
method and regeneration.

### 1.1 Size has not fallen, and that is the first finding

| measure | v53.1.7 | v61.0.3 | |
|---|---:|---:|---|
| `src/` lines | 607,285 | 674,299 | +11% (M) |
| backends, `sqlite.rs` + `postgres.rs` | 134,029 | 103,420 | -23% (M) |
| `admission.rs` | 28,123 | 32,346 | +15% (M) |
| `FederationDirectory` methods | 250 | 246 | (M) |

v56 to v61 finished the decision half of backend consolidation (#934): 91 doors
sit on shared plans, no door reads `identical`, and `MemoryBackend` is gone (T).
That work was necessary and it was not sufficient. Code moved out of the backends
and into the model, and each cut added new doors at the same time. The v61 target
of 95,000 backend lines was missed by 8,420 (M), and nothing failed, because
`size_report.py` is a report and `evidence/size.tsv` had gone stale (M).

Half the tree is tests. Of 674k lines, 342k are production and 333k are test code
inside `src/` (M). Production holds 213,713 lines of code and 113,410 of comments
(M), and 12,989 comment lines cite a ticket or version (#1144).

### 1.2 Where the complexity actually is

**The backends are not the main cost.** They hold 54.8k production lines; the rest
of their 103k is tests. About 13k lines per side are textually shared, and 309 of
498 paired functions are under 50% similar, because SQL text, bind syntax and row
decoding differ (M). A realistic prize for a dialect engine is 10-15k lines (B).
That is worth having, for clarity more than for size, and it is not half the
backends.

**The admission path is the largest structural item.** `plan_put_attestation` is
one hand-written sequence of about 880 lines over 19k production lines, with 96
`check_*` functions (M). There is no single value for "which family is this row":
161 `attestation_type` comparisons in 45 files, 35 `dimension.starts_with` checks
in 17 files and 8 separate rule tables each derive it again (M). No door reads
`reserved_rule`; of 92 reserved families, 57 have bespoke gates and 16 have none
built (T, census). Duplicate gates keyed differently are what produced #1174.

**The door stack multiplies everything else.** One concept crosses up to five
layers: trait method, backend, `Engine` (234 `pub fn`), `pyo3.rs` (717 functions)
and `directory_capsule` (74 ops). `BackendDispatch` arms number 270 in `engine.rs`
and 890 in `pyo3.rs`, with about 20 local `dispatch` macros in `pyo3.rs` alone (M).
`FederationDirectory` has 58 default bodies that return `Unsupported` and 14
family/community twins that `GroupKind` already parameterises below the trait (M).

**Answers are decided in several places.** The canonical retraction fold has 25
call sites, and at least 15 other deciders never call it (M). Whether those answer
differently is not yet known (B); §6 settles that. Thresholds are spelled twice
locally and called from 9 files, and windows such as 172,800 are literals in about
20 production files (M).

**Backends still decide some things.** Inside doors the scan calls gateless, 50
functions raise non-storage errors, 47 read their own clock and 23 fold (M, regex,
some are row decoding). A gateless door is not yet proved decision-free.

### 1.3 What wall time is made of

| cost | number | |
|---|---:|---|
| certify | 3,600-4,100 s | T |
| axis legs re-running the same ~4,000 core tests for 30-65 axis tests each | about 17 min per certify | B on the saving |
| one unhashed cdylib artifact rebuilt across feature sets | about 10 min per certify | T on the cost |
| tag CI, 61.0.3 | 63 min | T |

The biggest waste needs no refactor. The rest comes from structure: 49% of `src/`
compiles under `cfg(test)` for each feature set, and any witness edit rebuilds the
whole test library (81% of commits since v60.0.0 touched a test-only file, M).

The workspace split helps less than assumed. 76% of those commits touched model
code, which rebuilds every downstream crate, so a backend split alone helps about
1 commit in 5 (M). §10 orders the splits by what they actually pay.

### 1.4 What v62 adds to the pressure

CC 2.6.1.8 replaces the signed object. The reach of that change today has no seam:

| surface | count (M) |
|---|---:|
| raw envelope reads | 375 in about 60 files |
| `Attestation {` literals | 1,394 |
| signature-column references | 1,475 in 58 files, 629 in backends |
| `additional_scrubs` references | 228 in 25 files |
| id and row-hash derivations | 901 in 66 files |
| backend lines using JSON SQL into the envelope | about 160 |

So the order is forced. Without a typed row view, "read both forms" lands in 60
files; with one it lands in a codec.

### 1.5 What this rules out

- A backend-first refactor. It is the smaller prize and its columns are about to change.
- Splitting `admission.rs` now. #1130 deletes much of it, and 101 `cc_impl` rows
  would be re-pointed twice.
- Line count as the measure of success. v56 to v61 show lines can fall in one place
  while nothing gets simpler. §2 measures the cost of a change instead.

## 2. Goals, measures and non-goals

### 2.1 Goals

Every goal has a gate. v61's missed size target shows what a goal without one is
worth. "Now" values are from §1 and Appendix A. Targets marked (B) are estimates;
the first phase replaces them with measurements, and the ratchet then holds them.

| goal | measure | now | target | gate |
|---|---|---|---:|---|
| reduced complexity | sites touched to add a family on existing primitives | census: bespoke per family | one manifest row plus vectors, no Rust | vendor gate; AST rule refusing family literals outside the model |
| | sites touched to add a door | up to 5 layers | one definition plus executor statements | surface generation; parity scan |
| | production code lines | 213,713 | at least 10% net down, ≤192,000 (B) | ratchet in `evidence/size.tsv`, red on growth without a named reason |
| improved clarity | rule tables deciding family admission | 8 | 1 | AST rule |
| | places answering one lifecycle question | 15+ | 1, plus listed exceptions | §6 inventory gate |
| | ticket and version archaeology in comments | 12,989 lines | 0 outside `CHANGELOG` | from-disk gate, last slice (#1144) |
| better or neutral performance | named hot paths, §11 | baselines not captured | no regression beyond the noise band, budget ≤5%, each exception signed off | interleaved A/B per release |
| config-driven policy | families admitted by the interpreter | 0 of 191 | all, with named code primitives | vendor gate, no defaults |
| | door and queue agree | no queue exists | one predicate; `queue_sound` and `queue_complete` hold | property test over `transitions.json` |
| | node-local values reaching admission | not measured | 0 | AST rule on the interpreter's inputs |
| CBOR/COSE | emission | JSON/JCS | one COSE_Sign1 per signer; both forms read | CC and Verify vectors on both backends |
| | sites reading the signed form | 375 raw reads | one codec per form | AST rule |
| DRY backends | backend functions deciding | 50 raise, 47 clock, 23 fold | 0, or listed | scan widened to every storage trait |
| | column lists, row decoders | 21 + 15 spelled lists | one per table | AST rule |
| clear dialect engine | statements outside the catalogue | about 1,450 literals | 0 | catalogue gate |
| | statements proved on a real schema | none | all, both dialects | prepare gate |
| | hot statements with a pinned plan | none | named set | plan gate |
| clean install | files applied on a new node | 201 or 193 | 1 baseline | chain-equals-baseline gate |
| wall time | certify | 3,820 s | ≤2,300 s (B) | recorded per release |
| | witness-only edit rebuilds | the whole test library | the test crate | recorded |

### 2.2 Non-goals

- **New behaviour in a mechanical step.** A step that moves code changes no verdict.
  Where the family model changes a verdict, that is its own one-row diff (§5.5).
- **Family features.** The 34 v62 feature tickets are not the refactor. §15 sorts
  them, and many become manifest rows that cost little once the interpreter exists.
- **Reader policy.** CC 4.4 trust sets, composition and mute display stay out.
- **Rendering.** Strings, locales and the client live above persist (§8.3). Persist owns
  the predicate and the folds, not the words.
- **A second format change.** The window in §4 opens once. Anything that must freeze
  bytes goes through it or waits for the next edition.
- **Removing legacy verification.** CC 2.6.1.8 keeps it for ever. The goal is one
  contained codec.
- **An ORM.** §7 gives the reason.
- **A smaller test suite.** Tests move and consolidate; coverage does not fall.

## 3. Target architecture

### 3.1 The shape

```
 Rust API     Python     capsule ABI        submit, view, queue, sync (§8)
      \         |         /                 generated surfaces, no dispatch arms
       +--------+--------+
                |
              Engine                        the one public Rust API
                |
   row bytes -> codec -> RowView            §4: typed view, one codec per form
                |
            FamilyKey                       computed once, before any gate
                |
   enabled(family, state, standing)         §5: one predicate; the door asks it of one
                |        \                  transition, the queue of all of them
           primitives    folds              §6: one answer, with its provenance
                |
              Plan                          data: writes, projections, instants
                |
            executor                        §7: runs a plan, decides nothing
             /      \
       Dialect     Dialect                  one statement catalogue, one decoder set
       sqlite      postgres
```

Every row, from any door, takes the same path. A door differs only in the mode it
passes (`Local` or `Replicated { first_held_at }`).

### 3.2 What each layer owns

| layer | owns | must not |
|---|---|---|
| surface | names, argument and error mapping | judge, or know a backend exists |
| `Engine` | signer, node identity, the clock | reach past the plan layer |
| codec | exact signed bytes, verification, the view | be bypassed by any reader |
| family model | which rule applies to which row | read the clock, or read node-local config |
| primitives and folds | the rules code must state | be pure in name only: input is replicated signed state plus the instants passed in |
| plan | what will be written | touch a driver |
| executor | transactions, retries, error mapping, connection policy | refuse by rule, read a clock, fold |
| dialect | SQL text differences | hold any logic that is not about SQL |

This is the existing rule from `FSD/ROOM_ROSTER_AUTHORITY.md` carried to every plane:
every evaluator is a pure function of replicated, signed state, because every node
must reach the same verdict.

### 3.3 Crates at the end

| crate | holds |
|---|---|
| `persist-model` | row, codecs, family model, folds, plans. No driver dependency |
| `persist-sql` | dialect, catalogue, decoders, executor |
| `persist-sqlite`, `persist-postgres` | connection, driver binding, schema |
| `ciris-persist` | `Engine` and facade; the name consumers pin today |
| `persist-py` | the cdylib |
| `persist-conformance` | tests, vectors, fixtures |

The production graph already allows this: `federation` to `store` has 2 references
(M). §10 gives the order and the true cost.

### 3.4 What does not change

Wire semantics apart from CC 2.6.1.8, refusal tokens (§5.6), the two-backend promise
(no backend-only door), the SQLite connection model, bounded Postgres checkout, the
shipped-migration rule (I43), the release chain, and the rule that a row's signed
instant belongs to its signer and never decides re-admission.

## 4. The row: typed view, CBOR and COSE

### 4.1 The typed row view comes first

`RowView` is the one way to read a row. It exposes named, typed accessors: family
key, verb, signers, subject, instants, body members, edition. It has two constructors,
one per signed form. It extends the existing `EnvelopeCore` and `RowMirror`.

It lands before any format work, on JSON rows alone, with no behaviour change. The
375 raw reads move onto it, and an AST rule then refuses a new one. After that, the
second form is one new constructor.

The fixture builder goes with it. 1,394 `Attestation {` literals and 84+ signer
helpers become one builder, so a test states what a row means and the builder decides
the bytes. Otherwise #1205 rewrites hundreds of test sites by hand.

### 4.2 Signed bytes are the truth

CC 2.6.1.8: a verifier verifies the bytes it received, never a re-encoding of typed
fields. So an edition 2 row stores `protected`, `payload` and `signature` exactly as
received, and those bytes never change. Disclosures are not part of what is stored: they live on
the bytes plane (§4.5).

That removes the envelope from SQL's reach. About 160 backend lines use JSON operators
into it, and 61 sqlite lines use generated columns or `json_extract` in migrations (M).
Nothing tickets this today.

| option | for | against |
|---|---|---|
| A. keep a rendered JSON projection beside the bytes | every query keeps working; one rule for both editions | stores the payload twice for edition 2 |
| B. promote every queried member to a column, no JSON | smallest storage, typed SQL | every query rewritten at the moment the row changes |

**Recommendation: A, then promote.** Bytes hold the truth. `attestation_envelope` for an
edition 2 row is a rendered projection, never read for a verdict, and rebuilt byte-equal
from the bytes plus the disclosures still held (the `projection.rebuild = byte_equal` of the
family model). Erasure therefore rebuilds the projection, so an erased value cannot survive
in it. Hot members are promoted to columns afterwards, measured by §11. For an edition 1 row
the JSON remains the truth, unchanged.

The id also changes. An edition 2 id is a tagged SHA-256, where today's `attestation_id`
is 16 bytes as a UUID. Every foreign key and cursor over it must carry both. §4.8 orders
this; the shape is settled in the second-pass review with CC.

### 4.3 A quorum is several statements

`additional_scrubs` ends. Each cosigner's statement is a stored row over one payload,
and a fold counts them by person, as #1198 counts votes. `count_distinct_roster_scrubs`
is already one predicate with 9 callers, so this has one centre (M). The storage is
one payload row and one statement per signer, keyed by payload.

**The quorum key (ruled, rc17 `6dc2091`).** Each signer's statement has its own id, because
the header carries `kid` and `iss`. A quorum is found by the quorum key: SHA-256 over the
payload bytes alone, `["CEG-quorum-key/2", payload]`, in the same hash-agile `[-16, digest]`
form. Cosigners sign byte-identical payloads, so the key is shared. The quorum key is the
storage key for the shared payload row. The low-entropy salt is a payload member, `salt`
(16 bytes), bound by every signer, so neither the id nor the quorum key confirms a guess.

### 4.4 Legacy verification is contained, not removed

Every earlier row verifies as itself for ever. So the JSON/JCS path stays, as one codec
module behind `RowView`, chosen by kind and edition. Nothing outside the codec may know
JCS exists. Write paths for both forms exist only until emission switches. The second
read codec stays permanently, so it has to stay small.

**The anchor (ruled).** An earlier-form receipt or custody acknowledgement is accepted only
when anchored before the cutover, and the anchor is a provenance-log position, never a signed
instant. The cutover is the log position of the first new-edition statement the ceremony
registers. A receipt is accepted when the tree size it covers is at most the tree size at the
cutover; a custody acknowledgement when the row it acknowledges sits before it. A row never
logged has no anchor, and its earlier form is not accepted after the cutover.

### 4.5 Erasure is part of the format (ruled)

#914: nothing minted today is erasable, and that cannot be retrofitted. CC has ruled the form:
`draft-ietf-spice-sd-cwt`, exactly, which is the COSE-native shape of what `erasable.rs` already
does.

- A blinded member is absent from the payload. The payload carries `_sd: [+ digest]` in mint order,
  SHA-256 over each disclosure's deterministic encoding, where a disclosure is `[salt, name, value]`.
- **The #914 ruling stands (rc17 `4794d9f`).** A disclosure set is bytes, not a row member. The statement
  replicates with its commitment and without its disclosures. The set is held on the bytes plane under
  the object's consent edge, and erasure is the bytes-plane tombstone.
- Label -70005 in the unprotected header is only a presentation form, beside a statement for someone who
  may see it. It is never how a disclosure travels or is held.

**Must-mint classes come from the family model.** CC added a column, `blind`, checked at vendor time:
`["body.note"]` for the 178 families whose `erasure_route` is `dsar` or `purge`, `[]` for the 11 sealed
families, and a gap for the two ballot families (ruled value `[]`). Further members arrive with each family's
ruled row, as one-row diffs. Identifiers, instants, references and digests stay sealed. A sealed family's
`note` carries nothing a subject request could reach.

What this means for the build:

| consequence | |
|---|---|
| the mint path blinds by rule | `step` refuses a row that seals a member its family's `blind` column names |
| a verdict never depends on a blinded value | ruled: no fold, verdict or admission reads a blindable member, or nodes that erased it and nodes that did not would disagree |
| one quorum, one disclosure set | cosigners share a payload, so they share `_sd`, and the set is one object on the bytes plane |
| SQL over blinded members goes | they leave the payload; §4.2's projection only renders what is still held |
| reads handle absence | a display path that reads a member (`device:label`, a filename) must accept an erased one |
| the disclosure store is required | the #914 FSD, approved in September and never written, is no longer optional. It is a section of this program |

### 4.6 What rides the window

| item | rides | why |
|---|---|---|
| #1178 five v1-instant preimage families, genesis re-sign | yes | CC names one ceremony |
| 22 envelope domains and every other signed thing | yes | CC: all but the chunk trailer become COSE |
| #914 `_sd` digests and disclosures | yes | §4.5, ruled |
| #1098 F1 set-kind ordering | yes | deterministic CBOR does not sort a semantic set |
| low-entropy `salt` payload member | yes | CC 2.6.1.8, ballots and census cells |
| #1116 build manifest on an occurrence, #1158 (a) device link | if ready | signed-shape changes, each with outside dependencies |
| #1067 chunk AAD v2 | beside it | the chunk trailer is excluded; ruled for v62 on its own path |
| receipts as COSE Receipts | yes | CC 2.6.1.8; provenance and stream logs |
| features | no | §2.2 |

### 4.7 Who owns what

Verify owns the composite algorithm, the keys and the known-answer vectors, and publishes
first (CIRISVerify#326). Persist adds no cryptography. The request to Verify is to own
deterministic CBOR and `COSE_Sign1` encode and verify as well, so that two repos do not each
hold a canonical encoder. `ciborium` is already in `Cargo.lock` as a transitive dependency;
`coset` is not.

### 4.8 Order

1. `RowView` and fixture builder, on JSON (v61 behaviour).
2. Schema: `edition`, statement bytes, new id shape, quorum key; the rendered projection.
3. Read side: edition 2 verifies and folds, behind `RowView`. Nothing emits it.
4. Family migration, §5, reading only `RowView`.
5. Mint path blinds by rule; disclosure store exists.
6. Emission switch and ceremony, last.

A node of an earlier candidate reads only its own form, so step 6 is coordinated across
the fleet (§14). CC 2.6.1.8 now says so: emission switches at the ceremony, once every node
reads both.

## 5. The family model: config-driven policy

### 5.1 Three kinds of configuration

"Config-driven" must not mean "per node". Two nodes holding different policy would reach
different verdicts on one row, and the roster fold would split. So there are three tiers,
and they never mix.

| tier | examples | who sets it | changes by | may decide admission |
|---|---|---|---|---|
| family model | signer rule, lifecycle, placement, governance | CC, `manifests/family_model.json` | a CC tag and a persist vendor | yes |
| instance policy | a room's protocol, moderator quorum, `mesh_config` | signers, in rows | a signed row | yes |
| operator settings | pool sizes, retention floors, sweep cadence | the node operator | config file, restart | **never** |

A ruling becomes a manifest edit plus vectors at a CC tag (agreed on CC#189). An AST rule
holds the third line: nothing reachable from `interpret` reads operator settings.

### 5.2 The vendored manifest

Every column is required; a blank is refused at vendor time, not defaulted. `taxonomy_version`
and the registry hash are pinned. Vendor-time checks: kind profiles, the carries grid, and
incomparable family matches, which are refused there (a leaf over its parent stays order-free
at run time).

The manifest compiles to a static table. A build-time generator writes committed Rust, and a
gate proves it matches the vendored JSON. So a ruling appears in review as a readable diff,
and no row pays for JSON parsing (§11).

### 5.3 The interpreter is one predicate

CC 4.5.13 makes this smaller than a rule engine. A family's lifecycle is a list of
transitions: `(verb, from, to, roles, policy, widens)`. `manifests/transitions.json` is
derived from the family model: 191 families, 474 transitions and 22 gap cells at rc17
(draft 0), over five states: none, admitted, withdrawn, recanted, superseded.

```rust
enabled(family, state, standing) -> impl Iterator<Item = Transition>
step(held: &Held, row: &RowView, door: DoorMode, now: Instant) -> Result<Admitted<Plan>, Refusal>
```

`step` finds the transition a row claims and asks whether it is enabled. `queue` lists
everything enabled for a person. That is one predicate, and `formal/event_lifecycle`
proves the two agree: `queue_sound`, `queue_complete`, `door_is_queue`,
`stranger_sees_nothing`. CEWP calls the queue "the admission door run forwards". Today
persist has the door and no predicate a queue could reuse, so this claim
(`CLM-queue-is-the-door`, normative, no implementer) is built here or nowhere.

**The state processor (CC 4.5.13, rc17 `49a016b`).** The queue, the preview and the door are one function run
three ways, and a node holds one. State is the held row set; object state, standing and seated roles are folds
over it, never stored verdicts. A projection is a rebuildable cache and never the source of a verdict.

| run over | is |
|---|---|
| the transitions enabled for one person | the queue |
| a row before it is signed, with `Held` plus that candidate | the preview |
| a row that arrives | the door |

Plan and execute already give the commit flag CC asks for. `step` returns a plan; the door hands it to the
executor, and a preview drops it. So `Held` is a read overlay of store plus candidates, and nothing in a preview can
write. Signatures are outside `step`: the codec verifies before a row reaches it, and a preview has none to check.

There is no third outcome. A row under a non-self policy is admitted at once, and the object moves when the fold
meets the policy's numbers, so "pending" is what the view says afterwards: state unchanged, and what is missing.
Impact is the diff of the fold before and after, plus the family's undo columns, never a stored field. `now` is
the one outside input.

The remaining columns follow the grammar locked on CC#189:

| production | reads columns | answers |
|---|---|---|
| `unit` | signer, subject, cosign, placement, freshness | may this row exist |
| `bond` | `reference_rule` and the carries grid | may it cite what it cites |
| `rewrite` | transitions, lifecycle, governance | may it make this move |

A transition's `policy` names a row of `manifests/governance_policy.json`, the "five numbers
published as data", which `two_path` decides. A gap cell is closed to everyone until ruled.
A family with its own lifecycle (membership stages, the election, the halt) refines these
states in its chapter model, so draft 0's table is a floor, not the finished set.

Standing is the set of roles folded from held rows. All of this is integer arithmetic over
signed inputs, "checked by vectors", so no float reaches a verdict.

`Admitted<Plan>` is the only way to obtain a plan, so a missing gate is a compile error. That
closes #681 step 4. Rule 0b, the halt gate, is one primitive at the door. No door has a
halt gate today (T, census), so this is new behaviour and arrives as a named delta.

### 5.4 What stays code

A column selects a rule; it does not state an algorithm. Staying in code, as named primitives:
signature verification, the roster fold and `roster_event_standing`, tallies and instant runoff,
delegation walks, `two_path`, trust walks, and `derived` projections. A new primitive needs a
witness and a CC reference. The census found six clauses with no axis; each has been placed
(T). A column with no consumer is a defect in the manifest, and a primitive with no column is
a defect in the code. Both are checked.

### 5.5 Moving a family without changing it by accident

CC's manifest already carries a `code_v61` column. That gives a two-step move, per family:

1. **State today.** The row encodes what v61 does, including what the census calls wrong.
2. **Prove it.** Interpreter and bespoke gate run side by side over the vectors and a replayed
   corpus. Verdicts and refusal tokens must match exactly.
3. **Cut over.** The bespoke gate is deleted in the same commit.
4. **Rule it.** The row moves to CC's ruled value, as a one-row diff with its vectors and a
   changelog line.

Step 4 is where behaviour changes, and it is the only place. The census counts 157 of 169
admitted verb sets differing from the ruled table, so most families have a step 4. Doing it in one
commit with step 3 would make any regression unattributable.

Order: unenforced and any-key families first (86 + 37, the census's largest and simplest
groups), then the 17 table families, then the 49 bespoke ones, hardest last. #1115 is the first
row. `hard_case:` and the #1061 groups come early, because they carry live risk.

### 5.6 Refusals

Tokens are a public contract and do not change in a mechanical step. Terminal or retryable
becomes a property of the refusal, which is the list #1206 needs, and which Edge's retry
schedule depends on. Whether a family's refusal emits a `hard_case` row is a column, never a
door-local choice. Emission keys on the refused row, so a re-ask writes nothing new.

### 5.7 The family key, now

`plan_put_attestation` computes one `FamilyKey` at the top, from the row's dimension, and hands
it to every existing gate. This closes #1174 as a class without touching the gates one by one,
and it is exactly what the interpreter consumes later. Re-keying the 27 gates individually, as
#1174 proposes, is on the wasted-work list in §13.

It ships in 61.x, because it fixes a live defect. Peer `scores` rows with a `hard_case:*`
dimension reach `hard_case_events` today (read from code, not yet run). They carry their true
signer, so a peer cannot impersonate this node. But row ids are deterministic and a repeat
record is a no-op, so a peer might pre-empt an id this node would later use. That second
effect needs tracing through the store.

### 5.8 Room instance values

Room-level values live on the signed room record, not in config: consensus protocol, admission
mode, `founder_only`, moderator quorum, discoverability, `federating`, normative regime,
`dissolves_at`, declared cohort, and `licence_classes` (CC 4.4.3.2.8, rc17 `523617d`: each class with `legal_weight`,
read by the #1217 withdraw limbs). The before-state on #1130 lists the fields the record lacks.
Admission mode and `founder_only` exist today only as protocol forms.

## 6. One answer per question

### 6.1 Questions, not functions

A question has one owner. A site that appears to answer it either calls the owner or is
listed as a different question, with the reason. Each answer also says why: a fold returns
`Folded<T> { value, rows, rule }`, the atom CC's `view.cddl` requires (`provenance.rows`,
`provenance.rule`). So the provenance a client shows is what the fold actually read, not a
reconstruction.

| question | owner | today | moves |
|---|---|---|---|
| is this row live | `precedence::retired_ids` | 25 callers, 15+ other deciders, a SQL fragment with no cross-type precedence (#720) | deciders onto the fold, or listed; the `lifecycle` column writes it |
| what does a supersede chain resolve to | one resolver, new | none; type-keyed folds miss widened claims (#798) | §6.3 |
| do these signers meet this rule | `two_path` and `consensus::evaluate` over one count | 4 policy layers, threshold spelled in 2 places and called from 9 files | one count by person; `strict_majority` called once |
| who counts as one voice | the #1198 fold | by key in places | one fold for votes and cosign statements alike |
| how long is this window | `governance_policy.json` | numeric literals in about 20 files | named constants from the table |
| what is this person's standing | one standing fold | spread across doors | new, the input to `enabled` |
| which family is this row | `FamilyKey` | 161 + 35 + 21 derivations | §5.7 |
| which door is this | `DoorMode` | 3 carriers | §8.6 |

### 6.2 SQL must not be a second opinion

`lifecycle_predicate` answers "is this live" in SQL so a page can filter. It must stay,
because a Rust fold cannot page. So it has to be generated from the same rule, and a
witness has to drive both over the same rows. #720's divergent case, a superseder that
loses on precedence, has no such witness today.

The same applies to `list_attestations_referencing` and `list_composers_referencing_any`,
where withdraws and recants are named in per-backend SQL.

### 6.3 Finding real differences first

The survey measured that these sites skip the fold, not that they disagree. So step one is
a differential: a generator of row sets, run through each decider and the canonical fold.

- Same answers: the site moves to the fold.
- Different answers, and the site is wrong: a bug, fixed with its own witness.
- Different answers, and the question differs: listed with its reason.

Order-free folds are a requirement, not a preference: "Folds are order-free, so offline
disagreement resolves the same way everywhere." Each owner gets a permutation test.

#798 needs a ruling on its sub-question. Fixing half of it gives a revocation split-brain,
so it must land as one change.

### 6.4 What this does not merge

Roster standing, trust walks and delegation reach stay separate folds. They answer
different questions and share only the liveness owner. Merging them would hide that.

## 7. Plan/execute and the dialect engine

### 7.1 What the code looks like today

`lookup_community`, in both backends, is one statement that differs only by `?1`/`$1`, a
`cirislens.` prefix and the driver calls around it. The next function, `list_communities_for_member`,
is a real difference: `json_each` on SQLite, a GIN `@>` containment on Postgres. Both kinds
occur all through the code. There are about 1,450 statement literals (M).

So the engine has to do two things well: remove the accidental differences, and keep the real
ones visible.

### 7.2 Why SQL stays SQL

The usual answers do not fit.

| option | verdict |
|---|---|
| ORM | no. The query plan is load-bearing here. Past storms were fixed with `INDEXED BY`, `ANALYZE` and index shapes, so a layer that hides SQL hides the thing that fails |
| query builder | no. It adds a second language and still leaves JSON, containment and upsert to per-dialect escapes |
| compile-time checked macros | no. They need a database at build time, and they do not fit `tokio-postgres` plus `rusqlite` |
| **a plain statement catalogue with gates** | yes |

The best practice this follows: one logical statement, the exact SQL readable in one place,
differences explicit, and every statement proved against a real schema by a gate.

### 7.3 The engine

```rust
stmt!(LOOKUP_COMMUNITY,
      "SELECT {COMMUNITY_COLS} FROM {s}federation_communities WHERE community_key_id = $1");

stmt!(COMMUNITIES_FOR_MEMBER,
      sqlite:   "... EXISTS (SELECT 1 FROM json_each(members) ...)",
      postgres: "... members @> $1",          // V060 GIN index
      why:      "containment: json_each on sqlite, GIN on postgres");
```

| piece | job |
|---|---|
| `Dialect` | placeholder form, schema prefix, parameter binding. Nothing else |
| `stmt!` | one name and one text, or two side by side with a required reason |
| column consts | one list per table, used through `{COLS}` (21 + 15 spelled lists today) |
| `RowRead` | a driver-free row accessor, so each decoder is written once |
| `Exec` | `query_opt`, `query_all`, `execute` over a statement and typed params |
| error map | driver error to store error, one place per driver |

`Dialect` is not allowed to grow logic. A statement that needs a conditional at run time is
two statements.

### 7.4 One open design risk

`rusqlite` is synchronous and runs on blocking threads under the connection model, while
`tokio-postgres` is async. A shared door body must run on both, and a SQLite transaction must
stay on one thread. Two candidates:

- Door bodies are `async` over `Exec`, and the SQLite `Exec` never yields, so the future is
  driven to completion on the blocking thread.
- Plans become pure data, and each backend has one loop that runs them. Reads inside a
  transaction are the hard case.

This needs a spike on one door group before it is decided. Persist has been burned by runtime
crossings before (#580, #156), so neither is assumed safe.

### 7.5 Gates

| gate | proves |
|---|---|
| catalogue | no SQL literal outside `stmt!` in store code |
| prepare | every statement prepares on a migrated real database, both dialects, in the test run |
| plan | hot statements use the expected index on seeded data with statistics; asserts index use, not cost |
| decides nothing | a backend function returns only storage errors, reads no clock, folds nothing; scan widened to `ReadEngine`, `OutboundQueue` and the service traits |
| parity | a door has one body, or a listed reason |

The prepare gate replaces the class of bug the DDL replay exists to catch, and the plan gate
makes query shape a tested property. Today it is found in production.

### 7.6 What moves out of backends

Instants are passed in by the plan; a backend reads no clock (47 functions do). Raised
`InvalidArgument`, `Conflict` and `InvalidTransition` either move to the plan or are shown to
be row decoding. The 77 byte-identical shared-door thunks become generated.

### 7.7 Expected saving, stated honestly

10-15k lines (B), plus about 2.2k of thunks (M). The prize is that a reader can see the one
place SQL differs and why, and that a new column touches one list. It lands after #1205 because
its columns change under it, with one exception: column lists and decoders go first (§13).

## 8. One narrow surface

### 8.1 The surface should shrink, not just be generated

Generating 735 Python functions would tidy the wrong thing. CEWP and CC 4.5.13 say what a client
needs: "A client renders two served shapes, the view and the queue, holds the keys of its
deployment and no policy." Since planes became rows, nearly every write is the same act. So the
surface can narrow to four verbs:

| verb | meaning | replaces |
|---|---|---|
| `submit(bytes, door)` | verify, admit, store a signed row | most of the 25 `put_*` trait methods, 30 Python `put_*` |
| `view(object, viewer)` | rows and atoms with provenance | a large part of 79 `list_*` methods and 44 Python `list_*` |
| `queue(object, viewer)` | enabled transitions with derived impact | nothing; does not exist |
| `sync(...)` | replication cursors and apply | the cursor reads, `apply_replicated_*` |

Two more groups stay beside those four verbs:

| group | holds | rule |
|---|---|---|
| node operations | keys, blob bytes, streams, transport, retention, telemetry | small, each justified |
| local store | a host's own unsigned state (§8.2) | outside the row path; no family, no replication |

**This is a direction until it is measured.** The census sets the target, and no number is proposed before
Edge's is in. The consumers turn out to use three different surfaces:

| consumer | how it calls | census |
|---|---|---|
| Agent | Python, on `Engine` | 96 methods of 735 Python functions; `cirisgraph_*` 9; `cirisnode_*` 0 |
| Server | **Rust, the crate directly; no Python at all** | 132 module paths, 51 `Engine` methods, 62+ directory methods (an undercount), 301 `federation_directory` calls, `cirisnode_*` 0 |
| Edge | capsule and Python | pending |

Two consequences. The Python surface may shrink further than the table above suggests, because `cirisnode_*`
(33 functions) has no caller in either census so far. And Python is not the main surface: **the public Rust
module tree is.** Server uses `federation::admission` 73 times and `federation::envelope` 58 times, including
functions such as `owner_of`, `envelope_dimension` and `nodes_owned_by`. v62 deletes much of `admission.rs`, so
those uses need a home first. A named public API (`prelude`, Server's largest group already) replaces reaching
into modules, and a helper Server needs becomes a fold or a `RowView` accessor.

### 8.2 The fourth job: the local store

Agent's census (origin/main, 96 `Engine` methods, nothing from `cirisnode_*`, 9 from `cirisgraph_*`) shows
most of its use is its own local state, not signed rows: tasks, thoughts, correlations, tickets, WA
certificates, deferrals, incidents, the graph, the secrets store, TSDB consolidation. None of that is a
federation row, so `submit`, `view`, `queue` and `sync` do not apply, and a family model must not reach it.

So it keeps a named surface, generated like the rest and unchanged by v62's row work. It is not "the
rest of the surface", and it is not a candidate for removal by narrowing. Its per-table service traits are
already separate. What changes is that they get the same statement catalogue and parity scan (§7.5).

Server builds its `SqliteWaCertBackend`, `SqliteServiceTokenRevocationBackend` and `SqliteGraphBackend` from
`conn_handle()` at 5 sites, so that handle, or a replacement, is part of this surface.

Whether this store should leave persist is a real question and an owner decision (§16). It is not part of
this refactor, and it stays for this refactor (ruled).

Three things Agent's census exposes, which any change must respect:

- `secrets_*` and the `audit_*` chain are security-sensitive and move only with their witnesses.
- `run_legacy_graph_migration` is how an old home upgrades.
- Five TSDB consolidators are called by name through `getattr`. A text search for callers finds only
  strings, so a census must include them, and removing one fails at run time.

`cirisnode_*` has no Agent caller. `cirisgraph_traverse_k_hop` has none either. Both remain open until
Server's census confirms.

### 8.3 Where the line falls with Server

CC stages the client shapes on CIRISServer (#851, #853, #858), with no implementer named for
`CLM-queue-is-the-door`. Neither Server nor Edge has code for them yet (M). If Server rebuilds the
predicate, the rules are kept twice again. Proposed split:

| persist | Server |
|---|---|
| `enabled`, standing, the folds, atoms with provenance | serving, routes, locale |
| `impact` fields derived from the family model: audience, tier, direction, undo | `text-ref` strings, benefit and downside text |
| `submit`, door verdicts, refusal tokens | the answer states and client flow |

CC confirmed this at rc17, and Server confirmed it matches #851, #853 and #858.

**The callable.** Server needs the preview: `step` over `Held` plus a candidate, writing nothing, with `impact`
beside it (§5.3); #851 has nothing to call until it exists. It lands in v62, per family, as each family reaches the
shared predicate (§5.5). Shipping it in 61.x would mean a second predicate that the door does not use, which is
the fault this document exists to remove.

### 8.4 One definition, generated surfaces

What remains is defined once, and the Rust method, Python binding, `.pyi` stub and capsule op are
generated from it. Python calls `Engine`, so `pyo3.rs` holds no dispatch: its 890 arms and about 20
local macros go. `BackendDispatch` becomes internal, or goes in favour of `Arc<dyn ...>`, which
`Engine::federation_directory` already returns. It is public today and consumers may match on it,
so the census decides.

The capsule stays. A `dyn` vtable is not ABI-stable across the wheel boundary (#320), so the C-ABI
table is the real contract. Only its hand-writing goes.

### 8.5 Trait decomposition

`FederationDirectory` splits by plane, and the 17 executor traits are the model. The 58 default
bodies returning `Unsupported` go: a method is implemented or does not exist. The 14 family and
community twins collapse on `GroupKind`, which already parameterises them below the trait. The 3
`_unfolded` read twins go with #1001's leftover wide reads.

### 8.6 One door mode

```rust
enum DoorMode { Local, Replicated { first_held_at: Instant } }
```

This replaces three carriers of one fact: the `REPLICATED_GROUP_ROW` task-local, `GroupRowDoor` and
`WriteOrigin`. #1185 is not only a type change. CC requires the replicated door to bound by its own
first-held instant, so it changes behaviour, and it ships in 61.x for that reason.

### 8.7 The cost, and the recommendation

Edge references `FederationDirectory` in 69 files and `ciris_persist::` in 81; Server in 30 and 140, with
301 `federation_directory` calls and 73 uses of `federation::admission` (M). That is a real break, and for Server
it is larger than the Python view suggested. **Recommendation: it rides v62**, as one clean break with no aliases, since
both consumers adapt to the new row in that release anyway. Splitting it across two majors charges
them twice. The cost is a larger v62. This is an owner decision (§16), taken with the census in hand.

## 9. Schema: measured truth and clean install

### 9.1 Measure the schema

`store/schema_parity.rs` (1,331 lines) replays DDL in Rust to guess what a database will contain,
and the model has fallen short of the grammar before (#679). The replacement asks real databases.
Migrate each dialect, read `sqlite_master` and `PRAGMA table_xinfo` or `pg_catalog`, and compare the
two snapshots under a declared mapping of type differences. The source scan of INSERT columns stays.

This comes before any v62 migration, because v62 adds exactly the DDL that hits the replay's gaps.

### 9.2 Clean install: a schema baseline

The usual name is a **schema baseline**, or migration squashing. A new node applies one generated
snapshot of the schema at version N in place of V1..VN. An existing node carries on as it always has.

refinery has no such feature, so persist adds a small step before it runs.

| step | rule |
|---|---|
| detect | no persist history table **and** no persist table. Foreign tables are allowed: an embedded node can share a database (#1156). Any persist table without history is refused by name, never baselined |
| apply | one transaction under the existing migration lock, so two nodes racing on an empty Postgres cannot both win |
| record | history rows for V1..VN with their original names and checksums, from the shipped checksum manifest |
| hand over | refinery then sees a fully applied chain, validates it, and runs anything after N as usual |

Writing the real checksums is what keeps I43 whole. No shipped file changes, and a baselined node is
indistinguishable from one that climbed the chain.

### 9.3 The gate

A baseline is generated, never hand-edited. The gate builds one database from the chain and one from
the baseline, then requires identical schema snapshots (tables, columns, order, indexes, triggers,
generated columns, the V060 GIN indexes) **and** identical contents of every table. Contents catch seed
data. Only one sqlite migration holds a pure `INSERT ... VALUES` seed (V081, M); the 80 data-bearing
files are otherwise rebuild copies or backfills, which do nothing on an empty database. The gate proves
that where this sentence only asserts it.

Migrations embed per directory with no feature gating (M), so this is one baseline per dialect, not one
per feature set.

### 9.4 Boot steps

Rust work around the runner needs no baseline-specific path, and the gate covers each case on an empty
store: `repair_v070_checksum` (a baselined node holds the correct checksum), the #226 shard backfill
(an empty probe), `pre_purge_schema`, `run_v31_migration_at_boot`. Genesis seeding runs after migrations
and is unaffected.

### 9.5 Baseline point and retiring the chain

| stage | what happens |
|---|---|
| mechanism | ships with the first baseline, after the last v62 schema change. An earlier one goes stale at once |
| rolling | a later release may generate a newer baseline; the mechanism does not change |
| retirement | once every supported node is past N, the V1..VN files leave and the checksum manifest remains. A node below the floor is refused with a typed error naming the release to step through |

**Tables are not a contract.** Agent reads `federation_attestations` directly over its own sqlite3 connection
(`ciris_accord_metrics/services.py:1623`). That path is research-only, behind its own opt-in, and is the only
such read in Agent. A row or schema change would still break it without touching a binding, and no gate would
see it. Direct table reads move onto a binding before the edition 2 schema lands (#1207).

Server has no production table reads. It has 18 lines in its harness and tests, and operators diagnose the
canonical with read-only queries by column. Tests move onto reads. The operators' need is real, so a supported
read-only diagnostic surface replaces table knowledge before the schema changes.

Retirement is a separate decision, gated on the fleet census, and it is the point where 25k lines of SQL
and the V070 repair actually go.

### 9.6 What it buys, honestly

Not boot time. A fresh SQLite open costs about 248 ms today (T, `store/test_backend.rs`), and new installs
are rare. Postgres is unmeasured. The value is a single readable statement of the schema, the end of DDL
replay, faster Postgres test templates (B), and eventual retirement of the chain.

## 10. Crates and tests

### 10.1 Order by what each split pays

| step | pays | cost | when |
|---|---|---|---|
| 1. `persist-py` cdylib crate | about 10 min per certify (T cost, B saving) | low: few `pub(crate)` uses | before v62 code |
| 2. `pyo3.rs` into submodules, one dispatch | avoids certain conflicts with v62 surface work | low | right after 1 |
| 3. spike: move one large `*_invariants.rs` out of the lib | prices step 4 with real numbers | small | before committing to 4 |
| 4. `persist-conformance` test crate | a witness edit (16% of commits touch only tests) rebuilds one crate, and the lib stops compiling test lines per feature set | high: 114 of 115 invariant files need a backend, 952 `super::` refs, 39.9k lines of `test_support` | after fixtures consolidate |
| 5. `persist-model`, `persist-sql`, backend crates | an enforced boundary: an executor cannot reach plan internals | high: 216 `pub(crate)` names, 3,594 feature cfg sites | after v62 |

The honest finding on #1004: a backend split alone helps 1 commit in 5, because 76% of commits touch model
code and v62 is entirely model work. The value of step 5 is the boundary, not the build. It comes after v62
because v62 deletes many of the 216 names that would otherwise be widened and then removed.

### 10.2 Consumers do not notice

`ciris-persist` stays as a facade, so Edge's git dependency and Server's pin keep their name. Every path in
`cc_impl.tsv`, the from-disk gates, `rules/*.yml` and `scripts/` moves, which is §12's problem.

### 10.3 Tests

Half of `src/` is tests, and that is not the fault: 1462 green tests once carried live bugs, so test shape
matters more than count. The fault is placement and repetition. One fixture builder, one signer helper and
shared bodies across backends come first. The move to a crate comes after.

## 11. Performance and cycle time

### 11.1 Baselines first

No baseline exists for most of what this changes. Capturing them is the first technical act of the
refactor, before any change, on both backends, using the interleaved A/B rule (a blocked run cannot tell
a regression from a busy machine).

| path | why it could move | bench |
|---|---|---|
| `plan_put_attestation`, full admit | interpreter replaces the hand sequence | new |
| `apply_replicated_attestation` | same, on the receive path | new |
| keyset and paged reads | statement catalogue, rendered projection | `read_pool_bench` |
| `projection_for` | `RowView` (#728 open, about 19% slower) | `benches/projection.rs` |
| roster and tally folds | provenance capture, count by person | new |
| `retired_ids` | more callers | new |
| signature verify | composite, per statement | Verify's |
| row decode and store size | CBOR plus rendered JSON | new |
| `view`, `queue` | new paths; a queue on every screen | new |
| blinding and disclosure | 178 of 191 families; digest per member, disclosures stored apart | new |

### 11.2 Budget

No path regresses beyond its measured noise band, with a budget of 5%. An exception is named, justified
and signed off, never silent. The gate runs per release.

### 11.3 Where it may go either way

| better (B) | worse (B) |
|---|---|
| family key computed once, not 161 string compares | `Folded<T>` provenance allocates on hot folds |
| compiled table lookup in place of a sequence of probes | a rendered projection stores edition 2 payloads twice |
| typed view in place of `serde_json::Value` walks | `dyn` dispatch on a hot read |
| count over statements, not a sidecar parse | one row per cosigner; a quorum costs N rows |

The provenance cost is avoidable: a fold can take a recorder that is a no-op on the door path. Decide
that from the bench. The stored-form choice in §4.2 is re-measured once real edition 2 rows exist.

### 11.4 Wall time

| lever | saving | dependency |
|---|---|---|
| certify axis legs filter to axis tests, compile unchanged | about 17 min, plus 5 × 1,546 s of runner time (B) | none. Keep one full-union run, since this assumes axes do not change core tests at run time |
| cdylib crate | about 10 min | §10 step 1 |
| `mold` | not measured | operator |
| test crate | test-lib rebuild on witness edits | §10 step 4 |

## 12. Proof: how behaviour is held

A refactor of this size is safe only if a wrong move fails loudly. Each kind of change has its own proof.

| change | proof |
|---|---|
| mechanical move | no test body changes in the same commit; the suite stays green on both backends |
| `RowView` over a raw read | old and new agree over the fixture set; AST rule blocks the old form |
| family cut-over (§5.5) | interpreter and bespoke gate side by side: verdict and token equal across vectors and a replayed corpus. Then the gate is deleted |
| family ruling (§5.5) | one-row diff, CC vectors, mutation: flipping the axis fails a vector |
| door and queue | `queue_sound` and `queue_complete` as a property test over `transitions.json` |
| folds | permutation invariance per owner; differential against the fold (§6.3) |
| new form | Verify's KATs, CC's match vectors, both forms through the real write path |
| schema | measured snapshots; chain equals baseline |
| upgrade | a populated v61 store migrated forward and **booted**, not only unit-tested, with every row verifying as itself |

Standing rules carry over unchanged: test every backend; mutate the load-bearing logic and see the witness
go red; a two-node claim is proved by delivery through the planes; a check that cannot fail is a report. Each
handoff marks claims tested or believed.

**Corpus.** Vectors cover what someone thought of, so cut-overs also replay real rows. The proposal is a
scrubbed snapshot from a test mesh (§16).

**Moving gates and evidence.** 73 files read source at test time, and paths are pinned in tests, scripts and
rules (M). 425 evidence rows point at symbols, 101 of them at `admission.rs`. So a move must carry its gates
in the same commit, evidence rows travel with their symbols, and CC re-pins once: after `admission.rs` has
shrunk, not while it does. That is why §13 puts the split last.

## 13. Phases and order

No dates. Each phase ends on its exit criteria.

### Phase 0: now, on 61.x, no API change

Anything needed before the refactor ships as 61.0.4. A feature that belongs in v62, or that carries a wire
break, goes to v62 (Eric, 2026-11-05).

- Close the 25 and rescope stale tickets and milestones (§15). File what has no ticket.
- Security and live bugs: `FamilyKey` closing #1174, then #1206; #1185; #1139 first half; #791.
- Certify leg filter, `mold`. Size ratchet live, `evidence/size.tsv` regenerated by the release bump.
- Performance baselines (§11.1). Surface census (§8.1).
- Running beside this: #1198, the room lock, election and appointment (#1195, #1202), #1201, on rc17.

**Exit:** `FamilyKey` shipped; baselines recorded; census in hand; the §16 rulings marked "before build" made.

### Phase 1: enablers, on the v62 branch, no behaviour change

Opens when Edge tags v44.

1. #679 measured schema gate.
2. `RowView`, fixture builder, column lists and row decoders.
3. cdylib crate, `pyo3.rs` submodules, one dispatch.
4. Spike: the `Exec` question (§7.4). Spike: move one invariant file (§10).
5. `enabled` and standing over today's rows, unserved. #1159's fold reading with CC's answer.

**Exit:** the 375 raw reads gone and gated; v61's suite green, unchanged.

### Phase 2: the read side, the model and the surface (v62.0)

1. Verify publishes (CIRISVerify#326). Schema for edition 2. Read side behind `RowView`.
2. Vendor the family model. Migrate families per §5.5, simplest first.
3. Inside it, as rows or primitives and not as doors: #1173, #1061, #1100, #720, #798, #991's cosign rule,
   `Admitted<Plan>`.
4. `submit`, `view`, `queue`; trait decomposition; `DoorMode`. The one API break.

**Exit:** every family through the interpreter; bespoke gates deleted; v62 **reads both and still writes
JSON**; consumers adopted.

A node of an earlier candidate reads only its own form, so reading must reach the fleet first. CC ruled this
at rc17: a release that reads both and still writes the earlier form is the new candidate before its switch.

### Phase 3: the switch (v62.x)

1. The mint path blinds by rule and the disclosure store is live (§4.5).
2. Fleet census confirms the read-side floor.
3. Emission switch and the genesis ceremony (#1178), once.
4. Schema baseline generated from the final v62 schema (§9).

**Exit:** new rows are COSE; genesis re-signed; a new node installs from one baseline.

### Phase 4: after v62

Split what is left of `admission.rs` and `federation/mod.rs`, with one CC re-pin. Test crate. Model and
backend crates (#1004). Statement catalogue and dialect engine. Delete wide reads; remaining typed kinds and
legacy tables. Docs pass (#1144), last. Chain retirement when the census allows.

**Exit:** §2 measures all met, and `PLATFORM_ARCHITECTURE.md` rewritten to match.

### What must not be done first

| do not | because |
|---|---|
| split `admission.rs` now | #1130 deletes much of it; 101 `cc_impl` rows re-pointed twice |
| hand-write #991's cosign rule, #1100's deltas or #1173's room doors | each is a manifest row |
| re-key 27 gates one by one for #1174 | one `FamilyKey` closes the class |
| build `Admitted<Plan>` on today's trait | its shape changes at `step` |
| write #722's cursor witnesses for retired cursors | those planes are rows now |
| refactor the 312 gateless doors for line count before #1205 | 629 signature-column references there get rewritten |
| split `pyo3.rs` during v62 | guaranteed conflicts |
| build the dialect engine before the columns settle | same reason. Column lists and decoders are the exception |
| let Server rebuild `enabled` | the rules are kept twice again |
| emit v62 rows before blinding works | not retrofittable |

### Working rule

One integration branch and one CI run, with new pushes cancelling old runs. Agents build locally within the
guard and leave full lanes to CI. A downstream ask during the refactor becomes a ticket, unless Eric says
otherwise. Security fixes go to the maintained series and merge forward.

## 14. Downstream contract

What each repo gets, owes and loses. The questions are asked now, before build.

### Edge

**Gets:** one `submit` and one `sync`; typed terminal or retryable refusals from the model; a stable
`DoorMode`; a generated capsule.
**Breaks in v62:** the `FederationDirectory` shape (69 files), `ciris_persist::` paths (81 files), row ids,
quorum as statements rather than `additional_scrubs`.
**Owes:** the surface census; retry schedule against the terminal list; adoption of the read side before the switch.
**Questions:** which reads have no replacement in `view` or `sync`? Is one `submit` workable on the replication
path? Does the hold bound in CC 5.3.3.5 rule 9 need anything from persist?

### Server

**Census received.** Rust only; §8.1.
**Gets:** `enabled` with hypothetical runs and `impact`, standing, folds with provenance, a named public API. No
second copy of any rule.
**Breaks in v62:** the trait and module paths (30 and 140 files), especially `federation::admission`.
**Owes:** display reads that accept absent members; harness table reads moved onto reads.
**Waits on persist:** #851 needs `enabled`, which arrives in v62.

### Agent, Lens, CIRISNode

**Census received from Agent.** 96 `Engine` methods; `cirisnode_*` none; `cirisgraph_*` 9 of 10.
**Gets:** the local store surface kept and named (§8.2).
**Breaks:** the federation methods it calls (`list_attestations`, `list_scores`, `attestation_insert_local` and
others) move to the new surface. `sync` is replication and does not touch anything Agent reads today.
**Owes:** the direct `federation_attestations` read onto a binding (§9.5), and a fix to the dead
`resolve_scoped_consent` probe.
**Questions for Lens and CIRISNode:** which bindings are live?

### Verify

**Owes first:** alg id, composite and KATs (CIRISVerify#326).
**Asked:** own deterministic CBOR and `COSE_Sign1` too (§4.7), and the row-level vectors both forms replay.
**Questions:** when does #326 publish? Do you accept the codec?

### CC

**Gets:** one implementer of `CLM-queue-is-the-door`, evidence that moves once, census regeneration at the merged head.
**Has ruled:** quorum key, anchor, erasure form, two-step switch, the `blind` column, the §8.3 placement, at rc17
`6dc2091` and `4794d9f`.
**Owes:** ruled family rows and the gap cells; the rc17 tag to vendor.

### Ordering

```
Verify #326 -> persist v62.0 reads both -> Edge, Server adopt -> fleet floor confirmed
            -> emission switch + genesis ceremony -> schema baseline
```

## 15. Backlog disposition

109 open at v61.0.3, read against the code. Close-claims were read at the tag and not executed.

| bucket | count |
|---|---:|
| close now | 25 |
| refactor | 8 |
| v62 | 34 |
| 61.x | 30 |
| parked | 12 |

**Close (25).** 21 closed 2026-11-05: #854, #934, #1063, #1122, #1123, #1125, #1126, #1127, #1136, #1141, #1146,
#1148, #1155, #1156, #1157, #1160, #1161, #1166, #1182, #1184, #1193.
Four stay open for now. #991, #1101 and #1143 hold staged CC claims (`CLM-goal-on-base`, `CLM-serve-seat-announced`,
`CLM-affiliation-public-face`, `CLM-affiliation-dissolution`), and CC's gate refuses a staged claim on a closed
ticket, so they close with their evidence rows in 61.0.4. #1140 waits for Server to confirm the deadlock is broken.

**Refactor (8).** #679, #681, #720, #722 (rescope), #798, #1004, #1144, #1185 (ships early).

**v62 (34), which is mostly not the refactor:**

| group | tickets |
|---|---|
| the program | #1130, #1205 |
| rides the format window | #1178, #914, #1098, #1067, #1116 |
| becomes a row or primitive | #1100, #1115, #1131, #1149, #1150, #1152, #1154, #1173, #1174, #1186, #1191, #1217 |
| committed for v62 | #1121 (CEWP: "The base lands with the substrate's next version"), #1118, #1142 |
| waits for the model, then cheap | #962, #974, #976, #1079-#1083, #1085-#1088, #1175 |

**61.x (30), by priority:**

| group | tickets |
|---|---|
| room governance | #1198, #1195, #1202, #1201 |
| live bugs | #1139, #791, #1159 (needs CC), #1061, #795 |
| adopters | #1163 + #1176 + #1190 as one door, #1179, #1181, #1183, #1204, #1206, #1147 |
| evidence | #803, #1197, #812 |
| tests | #1188, #1138 |
| low, won't-do defensible | #708, #727, #728, #747, #800, #890, #1177 |

**Parked (12).** #147, #415, #672, #1005, #1049, #1084, #1089, #1129, #1133, #1134, #1151, #1158. Each waits on a named
repo or ruling. #976 and Edge#826 block each other, and persist has to move first.

**To file, no ticket today:** view and queue doors (`CLM-queue-is-the-door`); SQL reading inside the envelope; performance
baselines; schema baseline; statement catalogue; surface census; certify leg filter.

## 16. Open decisions and risks

### 16.1 Decisions

| # | decision | owner | recommendation | needed by |
|---|---|---|---|---|
| 1 | the API break rides v62, once | Eric | **ruled yes** | |
| 3 | stored form: signed bytes plus a rendered JSON copy | Eric | option A (§4.2); proceeding on it, cheap to change until Phase 2 | Phase 2 |
| 4 | committed features | Eric | **ruled:** pre-refactor needs ship in 61.0.4; a feature that fits v62 or breaks the wire goes to v62, including #1121, #1118, #1142 | |
| 6 | a scrubbed corpus from a test mesh | Eric | **ruled yes** | |
| 7 | `mold` on CI and certify | Eric | **ruled yes** | |
| 11 | ruled family rows for the gap cells | CC | gaps closed until ruled; refinements land as rows with vectors | Phase 2 |
| 12 | Verify owns CBOR and COSE encode | Verify | yes (§4.7) | before build |
| 13 | the persist and Server line | Server, CC | §8.3 | Phase 1 |
| 14 | surface census | Edge | Agent and Server done | Phase 0 |
| 15 | the local store stays in persist for this refactor | Eric | **ruled yes** (§8.2) | |

### 16.2 Risks

| risk | effect | response |
|---|---|---|
| Verify's #326 slips | Phase 2 cannot start | Phase 1 and the family model do not depend on it, so they proceed |
| ruled family rows arrive slowly | step 4 of §5.5 stalls | steps 1-3 run on `code_v61`; the cut-over proceeds and rulings follow |
| the composite draft changes construction | signed bytes move | hold the switch until it is stable. CC says only the id changes later, so this is a question for Verify |
| v62 becomes too large | a long-lived branch, drift from 61.x | merge forward each patch. The switch is already split out. Family migration can pause cleanly between families |
| the `Exec` spike fails | the dialect engine shrinks to column lists and decoders | acceptable. That step alone carries much of the clarity |
| interpreter misses budget | §2 not met | compile further; a family keeps a code primitive with a listed reason |
| adopters hit step 4 changes | surprise refusals | each is a named delta with a changelog line, and goes through CC |
| persist's vendored CC lags (rc15, with rc17 open) | manifest drift | vendor at tags, re-pin with an Adoption line |
| quorum rows multiply storage | §11 budget | measured; statements share one payload row |

## Appendix A. Measurements

All at v61.0.3 (`7894b39c`), 2026-11-05. The tools are currently in a scratch directory and must enter `scripts/` before
this FSD merges, so that §1 can be regenerated.

| number | method | class |
|---|---|---|
| 674,299 `src/` lines; history by tag | `git grep -c ''` | M |
| 341,870 production, 332,979 test, 213,713 code | comment- and string-aware scan following `cfg(test)` modules | M |
| 103,420 backends; 54.8k production | same | M |
| 246 trait methods, 58 `Unsupported` | trait parse at depth 1 | M |
| 91 shared, 0 identical, 1 declared, 310 gateless | the real parity scan at v61 | T |
| 84 / 312 | a Python port, approximate | M, approximate |
| 13k shared lines per side; 309 of 498 pairs under 50% | normalised textual comparison, not semantic | M, approximate |
| 50 raise, 47 clock, 23 fold | regex; some are row decoding | M, approximate |
| 161 + 35 + about 21 family derivations | grep, part hand-counted | M, approximate |
| 375 raw reads, 1,394 literals, 1,475 signature refs | grep, production unless stated | M |
| about 160 JSON SQL lines; about 1,450 statement literals | grep and regex | M, approximate |
| 76% model, 81% test-only, 20% no-model commits | 127 commits, v60.0.0..v61.0.3; test-only by filename | M |
| census figures | `release53/v62_census`, on #1130 | T |
| 191 families, 474 transitions, 22 gaps | `manifests/transitions.json` at rc17 `d73840d` | M |
| certify and leg times | release records | T |
| 248 ms fresh open, 7.1 ms clone | `store/test_backend.rs` | T |
| 10-15k dialect saving; 17 and 10 min | estimates | B |
| 10% code reduction target | sum of estimates: dialect 10-15k, dispatch and thunks about 6k, admission net of new code | B |

Sources: `FSD/KEY_PLANE_ROWS.md` and `FSD/ROOM_ROSTER_PLANES.md` §7 (per-plane specs); CC 2.6.1.8, CC 4.5.13;
`signed_object_v2.cddl`, `view.cddl`, `choice_item.cddl`, `transitions.json`, `governance_policy.json`, `family_model.json`;
`formal/event_lifecycle`; CC#189; https://cirisai.github.io/CEWP/.

