# FSD — Trust-root security under CC rc6: attach freshness, witnessed lineage, liveness margin (v51.0.0)

CIRISPersist#937 (CC 3.2 T4a, CIRISConstitution#118), #938 (CC 3.2 T6 / 5.3.1, CIRISConstitution#119), #939 (CC 3.2 T7, CIRISConstitution#120). The rulings sit on CC branch `rc6` and land on `main` at the rc6 cut; the persist tickets carry their full text, and this document builds against the tickets. The T8 mechanized model (CIRISConstitution#127) is CC's; persist's five review corners are on that ticket.

Operator (2026-09-28): v51.0.0 is the release adopters take ("no one adopts 50"); it carries the full rc6 security set so the mesh can roll its final state. Companion: CIRISServer#693 (the cosign route and the head served beside the bundle). Persist ships the object, its verifier, the store, the fold, the doors and the hard cases; the two-node witnesses use persist's own directory as the witness plane, so nothing here waits on Server.

## 0. The three rules in one sentence each

| Rule | One sentence | Gate or fold |
|---|---|---|
| **T4a attach freshness** (#937) | Attaching a root needs a WITNESSED lineage head no older than the root's charter-declared `attach_window`; once attached, T4 governs — valid until revoked, never a timer. | Gate, on the acceptance edge only. |
| **T6 witnessed lineage** (#938) | The current head of a conferring lineage is the latest WITNESSED head; an unwitnessed competitor is held, not adopted; two witnessed heads freeze the lineage at their last common ancestor and raise `hard_case:lineage_equivocation`. | Fold, plus the cosign object and its doors. |
| **T7 liveness margin** (#939) | A trust-root-grade community is live at ≥ M+1 active founders and STALLED at ≤ M; stalled is declared (`hard_case:community_liveness_stalled` / `_restored`), valid but non-admitting; founding needs N ≥ M+1; a floor that raises M is refused for `infrastructure`. | Fold + founding gate + emitter. |

Trust assumption, stated once: the witness set is a second, independent roster — `identity_type ⊇ {witness}` (CC 3.4.10 already reserves `transparency_log:cosigned:{tree_size}` to it), never a founder of the lineage it witnesses. A lineage witnessed solely by its own founders is unwitnessed.

## 1. Objects and storage

### 1.1 The lineage head

A **lineage** is a conferring family (`humanity-accord`, any family whose charter confers) or a trust-root-grade `infrastructure` community (`ciris-canonical`, any `infrastructure_constraint` row). Its **head** is the latest roster-chain record: for a community, the current `SignedCommunity` version; for a family, the current signed family record. The head is identified by:
- `head_digest_sha256_hex` = the record's `persist_row_hash` (SHA-256 over the JCS-canonical signed record persist already computes and stores — no second canonicalisation);
- `head_asserted_at` = the record's signer-stamped instant (`amended_at` for a link, `founded_at` for a birth; the family record's own signed instant).

### 1.2 `LineageHeadCosign` — `ciris.lineage_head_cosign.v1`

```
LineageHeadCosign {
  lineage_key_id            string     the community_key_id or family_key_id
  head_digest_sha256_hex    hex64
  head_asserted_at          RFC 3339   the head's signer-stamped instant
  prior_head_digest_sha256_hex  hex64?  the head this witness last cosigned for this lineage (absent on first)
  signed_at                 RFC 3339   the witness's signer-stamped instant
  witness_key_id            string
  signature_classical       base64     Ed25519 over the domain-labelled canonical bytes
  signature_pqc             base64?    ML-DSA-65 over canonical ‖ ed25519_sig (hybrid-Strict as everywhere)
}
signed bytes = JCS({domain: "ciris.lineage_head_cosign.v1", lineage_key_id, head_digest_sha256_hex, head_asserted_at, prior_head_digest_sha256_hex?, signed_at, witness_key_id})
  — the domain label is a SIGNED MEMBER of the envelope (persist's `verify_envelope_hybrid_signature` over JCS, as every signed object), so an STH cosign (no such member) never verifies here and vice versa. Server#693's route signs the same envelope.
```
The domain label is distinct from `ciris.sth_cosign.v1` (persist's `witness` module is the STH witness; this object never verifies there and vice versa — pinned by a witness that feeds each object to the other verifier).

Storage: **V159** `federation_lineage_head_cosigns` on both dialects — PK `(lineage_key_id, head_digest, witness_key_id)`, columns as above, `admitted_at` (node-local, never read by a verdict). Bytes pinned in `evidence/migration_checksums.tsv`.

### 1.3 Charter members (T4a)

`trust:charter:v1` (the self-loop `delegates_to` with `infra:` scope) gains two typed envelope members, carried in the scrub-signed bytes so changing either is a charter re-scrub by the conferring roster, refused as a plain config edit:
- `attach_window_secs: u64` — the freshness window for attaching;
- `witness_cadence_secs: u64` — the re-commit cadence (T6 §3);
- `witness_quorum: u32` (optional) — how many independent witnesses make a head "witnessed". **Absent or `0` is witnessed mode off (§8, CIRISPersist#973); persist substitutes no default.** A value of `1` is refused at charter admission.

They are typed members of `EnvelopeCore` (`paths::ATTACH_WINDOW_SECS`, `paths::WITNESS_CADENCE_SECS`, `paths::WITNESS_QUORUM`), so **`ENVELOPE_VOCABULARY_SHA256` re-pins** (the I120 discipline: the test that asserts the pin stays; the CHANGELOG names old and new). Shipped defaults for `ciris-canonical` / `humanity-accord`: `attach_window_secs = 604800` (7 d), `witness_cadence_secs = 86400` (24 h) — CC 5.3.4. A charter that declares no `attach_window_secs` makes its root attachable only through an out-of-band anchor naming a specific head (T5).

## 2. Doors

### 2.1 `put_lineage_head_cosign(cosign) -> LineageCosignOutcome { Inserted | Unchanged | Refused { reason } }` (trait, all backends; Engine; pyo3 `put_lineage_head_cosign_json`; capsule op appended)

Admission, in order, each a typed reason (`Error::LineageCosignRefused { lineage_key_id, witness_key_id, rule }`, kind `federation_lineage_cosign_refused`, Python `ValueError`):
1. `witness_not_registered` — `witness_key_id` has no registered key record here.
2. `witness_not_witness_type` — its `identity_type` does not contain `witness`.
3. `witness_is_founder` — the witness is a founder of the lineage (record founders at the head, or any version of the chain it names) — the independence rule.
4. `signature_invalid` — hybrid verification over the domain-labelled canonical bytes fails.
5. `head_unknown` — this node holds no version of the lineage with that `head_digest` (held, not adopted: the cosign is stored but the head it names is not one this node can judge — see §3.2; stored so a later arrival of the head is already witnessed).
6. `head_instant_mismatch` — `head_asserted_at` ≠ the held head's signer-stamped instant.
7. `prior_not_ancestor` — `prior_head_digest` names a version that is not an ancestor of the head in the chain this node holds (Server's `422 LINEAGE_HEAD_INCONSISTENT`; persist refuses the same way). A cosign whose prior names a DIFFERENT witnessed head of the same lineage is not refused — it is stored and is the equivocation evidence (§3.3).
8. `skew` — `signed_at` outside CC 2.6.7's ±5 min of `now`, or before `head_asserted_at`.
Identical re-put → `Unchanged`. No cosign is ever deleted (evidence).

### 2.2 The acceptance edge (T4a)

`check_attach_freshness(dir, delegates_to(node → root) carrying trust:accepts:v1, presented_head, now)` runs inside the existing `trust:accepts:v1` admission (the `delegates_to` door), BEFORE the edge is stored:
- the caller presents the head it attaches under (`presented_head`: the head record + its cosigns; through the capsule op and pyo3 as the bundle response's `lineage_head` object, CIRISServer#693 §3);
- refuse `trust_root_head_stale` when `now − head_asserted_at > attach_window_secs` (measured against the SIGNER-stamped instant under the CC 2.6.7 skew rule — never the consumer's clock alone), or when the head is not witnessed (fewer than `witness_quorum` valid cosigns from independent witnesses after §2.1's admission);
- **the gate is ARMED by the charter**: a charter that declares no `attach_window_secs` is a pre-rc6 charter, and an edge naming no head under it is the pre-rc6 shape — admitted, stated (the mixed-fleet allowance: every consumer edge in the field today names no head). Once the conferring roster re-scrubs its charter with a window (the shipped default for `ciris-canonical` / `humanity-accord` is 7 days), every attach needs the witnessed head. An edge that names a head (`attached_head_digest`) is judged under any charter — that is the T5 out-of-band anchor;
- **nothing on the attached side changes**: `trust_root_valid` MUST NOT read the window, the cadence or drill staleness (I-witness: an attached node whose head goes stale stays `Rooted`).
`freshness.rs` stays a monotonic lower bound.

### 2.3 Founding and floors (T7)

- `put_community` / `apply_replicated_community`: a trust-root-grade `infrastructure` row founded at N ≤ M active human founders is refused — rule `liveness_margin_at_founding` on `CommunityConsensusProtocolViolation` (N ≥ M+1 is the conformance floor; composes with #927's `N == founder count` and #925's node-bearing exclusion).
- `family_charter_threshold` flooring at strict majority, or an unknown protocol read as unanimity, RAISES effective M — refused at admission for `infrastructure` (`liveness_floor_raises_m`), never applied silently (#927 ask 2 resolved).
- Recovery is by the conferring body only (for `ciris-canonical`: the accord's co-scrub conferring a replacement founder, T2); never by lowering M (entrenchment), never by members.

## 3. The fold

### 3.1 Active founders and the margin (T7)

`active_founders_at(now)` = record founders − resignations (every instant kept, #926 round 8) − `withdraws` − `revoked_after` bounds − node-bearing seats (#925) — the same inputs `compute_standing` reads, at the same explicit `now` (round 9). `liveness = Live if |active| ≥ M+1; Stalled if |active| ≤ M`. `StoredStanding` gains the margin as a field, NOT a new state: `Rooted { live: bool }` — a stalled root is **valid but non-admitting** (`trust_root_valid` ignores `live`; `admit_community_change` requires `live` — nothing new is conferred until restored). The cache key already covers every input; `valid_until` already bounds every instant (round 9).

### 3.2 The witnessed head (T6)

`witnessed(head)` = ≥ `witness_quorum` admitted cosigns for `head_digest` from distinct independent witnesses. The fold's **current head is the latest witnessed head** of the chain this node holds:
- a version this node holds that is not (yet) witnessed is HELD, not adopted: `stored_standing` judges the chain up to the latest witnessed version; the unwitnessed tail is reported (`StoredStanding::Rooted { unwitnessed_tail: n }`) and served nowhere. First-seen-wins is retired for conferring lineages; ordinary rooms are unchanged.
- **Exception, stated:** a lineage with NO cosign at all (pre-rc6 rows; a fresh mesh before its first witness) is judged as today — the rule engages once the lineage has ever been witnessed (`ever_witnessed`), so the upgrade cannot un-root every node at once (the failure T4 forbids). CHANGELOG names it.
- **cadence:** a lineage whose latest cosign `signed_at` is older than `witness_cadence_secs` is *silent* — reported on the trust surface (`resolve_community` / the bundle response: `witness_silent_since`) as a liveness signal, never a validity leg.

### 3.3 Equivocation (T6)

Two witnessed heads for one lineage, neither an ancestor of the other (each founder-quorum-signed, each with ≥ quorum cosigns): the fold **freezes the lineage at the last common ancestor** (the latest witnessed version both descend from) — that is the current head; standing is judged there; nothing past it is adopted or served — and the substrate emits `hard_case:lineage_equivocation:{lineage_key_id}` under the CC 3.4.2 emitter rule (`identity_type = substrate_persist`), payload: both head digests, their instants, their cosign sets (the evidence object for adjudication; CC 3.3.10.1 ledger shape). A consumer holding a witnessed head refuses a competing UNWITNESSED head (`does_not_extend`, as #926 round 10's `extends`) and never adopts a first-seen fork. Emitted once per (lineage, pair), idempotent.

### 3.4 Restore discipline (T6 §3)

After a restore, a founder node re-syncs its head from the witness plane before writing: `put_community` on a trust-root row refuses `lineage_head_behind_witness` when this node holds cosigns for a head digest it does not hold the version of (the witness plane knows a later head than this node) — the founder must fetch before extending, so a restored node's `supersedes` produces a detectable non-descendant, not a silent fork. The witness: a restored node with an older head writing a supersede is refused; after the fetch it extends.

### 3.5 Stalled is declared (T7)

At the transition Live→Stalled the substrate emits `hard_case:community_liveness_stalled:{community_key_id}`; at Stalled→Live `…_restored:{community_key_id}`; every fold reproduces the verdict from rows alone (the hard case is a report of the transition, never an input). Emitted from the read that observes the transition (idempotent per (community, transition instant)) and from the roster/record doors that cause it.

## 4. Surfaces (as built)

- Trait: `put_lineage_head_cosign(cosign) -> LineageCosignOutcome` — a defaulted method whose body IS the door (`lineage_witness::admit_lineage_head_cosign` at the door's one clock read), so the capsule proxies it and no backend overrides it; `store_lineage_head_cosign` / `list_lineage_head_cosigns_for` — defaulted `Unsupported`, overridden by memory / sqlite / postgres (V159).
- Engine: `put_lineage_head_cosign`, `lineage_head(id) -> Option<WitnessedHead { judged, unwitnessed_tail, equivocation, latest_cosign_at }>`; `resolve_community` gains `live`, `witnessed`, `unwitnessed_tail`, `equivocation`, `witness_silent_since` (the served row of a trust root is its WITNESSED head, which may be an ancestor of the stored row).
- pyo3: `put_lineage_head_cosign_json`, `lineage_head_json`; the resolve dict carries the five fields.
- Capsule: `PutLineageHeadCosign` op + `LineageCosignOutcome` result APPENDED (growth; digests re-pinned; ABI 6).
- Standing: `StoredStanding` is unchanged in shape; `Rooted` boxes the JUDGED (witnessed) head; the liveness margin is `resolve_community.live`; the transition hard cases are emitted from `stored_standing_at` against the last verdict the cache OBSERVED per community (keyed by id).
- Charter members: typed `EnvelopeCore` fields (`attach_window_secs`, `witness_cadence_secs`, `witness_quorum`) + `attached_head_digest` on the edge — `ENVELOPE_VOCABULARY_SHA256` re-pinned; `canonical_community::charter_members_for(root)` reads them from the charter row this node holds for the root, falling back to the accord family's charter for a community root.
- Migration V159 (both dialects). Evidence rows at CC 3.2: `CLM-attach-freshness`, `CLM-witnessed-lineage`, `CLM-liveness-margin`.

## 5. Invariants (I191–I196; memory, sqlite, postgres unless stated)

- **I191 cosign door**: each of §2.1's eight refusals; identical re-put `Unchanged`; the STH verifier refuses a lineage cosign and vice versa (domain separation); a cosign for an unknown head is stored and becomes effective when the head arrives.
- **I192 witnessed head**: an unwitnessed extension is held (standing judged at the witnessed prefix, tail reported); one cosign from an independent witness adopts it; a founder's own cosign does not count; `witness_quorum: 2` needs two witnesses; the `ever_witnessed` exception — a never-witnessed lineage is judged as today.
- **I193 equivocation** (two nodes + a witness): founders sign H2 and H2′ over the same prior; each gets a cosign; a node holding both freezes at H1, emits `hard_case:lineage_equivocation` once with both digests and cosign sets, serves H1, refuses to extend past it; a node holding H2 witnessed refuses H2′ unwitnessed as `does_not_extend`.
- **I194 attach freshness**: attaching under a head inside the window with a cosign → the edge is stored; the same head one second past the window → `trust_root_head_stale`, nothing stored; a fresh unwitnessed head → `trust_root_head_stale`; an ATTACHED node whose head goes stale stays `Rooted` and `trust_root_valid` is unchanged (the T4 leg, mutated: the window read inside `trust_root_valid` must be KILLED by this arm); a charter with no window → refused without an anchored digest, admitted with one; changing `attach_window_secs` by a plain re-put is refused as a charter change.
- **I195 liveness margin**: `quorum:2/3` with 3 founders → live; one resignation → `Rooted { live: false }` + `…_stalled` emitted once, `trust_root_valid` still true, `admit_community_change` refused; the ceremony-plane conferral of a replacement founder → live + `…_restored`; founding at N=2, M=2 refused (`liveness_margin_at_founding`); a strict-majority floor that raises M refused for `infrastructure`; a `geographic` room is untouched by all of it.
- **I196 restore**: a node restored to an older head that holds a later cosigned digest refuses its own supersede (`lineage_head_behind_witness`) and extends after fetching the head.
- From disk: the window/cadence are read at exactly one site (the acceptance edge / the surface) and never under `trust_root_valid`; the hard cases are emitted under the substrate emitter rule only.

## 6. Mutation plan (≥ 18)

Domain label dropped (STH cosign accepted as lineage cosign); founder-witness admitted; `witness_quorum` ignored; unwitnessed tail adopted; equivocation freeze skipped (latest wins); hard case not emitted / emitted with one digest; window compared against node-local admitted_at; window read inside `trust_root_valid`; stale head attaches; `live` computed at M instead of M+1; founding floor N ≥ M admitted; floor-raises-M applied silently; stalled hard case not emitted; restore check dropped; `ever_witnessed` exception widened to always-unwitnessed; cosign for unknown head dropped instead of stored; prior-not-ancestor admitted; skew unchecked.

## 7. Mixed fleet, adopters, residuals

- A v50 node adopts unwitnessed heads first-seen-wins; a v51 node holding a witnessed head refuses a v50 peer's unwitnessed competitor. Until the first witness cosigns a lineage, v51 behaves as v50 (`ever_witnessed`).
- Server#693 serves the cosign route and the head beside the bundle; Edge attaches through `pin_trust_from_bundle_response`; the canonical node re-commits both lineages at least once per cadence (Server).
- Residual: the witness set's own standing is judged by `identity_type` and non-foundership only; a witness's revocation un-counts its cosigns from its `revoked_after` (every instant keyed, `valid_until`-bounded).
- `witness_quorum`: superseded by §8 — silence and `0` are witnessed mode off; there is no default.

### 6.1 Mutation round (v51.0.0, on the committed tree; lane = rc6 + v51 + I190 + media + #929 witnesses on memory, sqlite, postgres)

| # | Mutant | Verdict | Killed by |
|---|---|---|---|
| W1 | witness type check dropped | KILLED | memory::i191, postgres::i191, sqlite::i191 |
| W2 | founder may witness | KILLED | memory::i191, postgres::i191, sqlite::i191 |
| W3 | signature not verified | KILLED | memory::i191, postgres::i191, sqlite::i191 |
| W4 | skew unchecked | KILLED | memory::i191, postgres::i191, sqlite::i191 |
| W5 | head instant unchecked | KILLED | postgres_dyn::i190_o3, postgres_dyn::i190_o4, postgres_dyn::i190_p, postgres_dyn::i190_q, postgres_dyn::i190_r, postgres_dyn::i190_t, postgres_dyn::i190_u, postgres_dyn::i190_v |
| W6 | prior ancestry unchecked | KILLED | memory::i191, postgres::i191, postgres::i193, postgres::i195b, postgres::i196, sqlite::i191, v51_invariants::descriptor::postgres::i122, v51_invariants::postgres::i125_a_failed_projection_rolls_the_row_back_on_postgres |
| W7 | domain label dropped from the envelope | KILLED | lineage_witness::tests::the_domain_label_is_a_signed_member |
| W8 | quorum ignored (any count witnesses) | KILLED | lineage_witness::tests::witnessed_counts_distinct_independent_witnesses |
| W9 | founders count as witnesses | KILLED | lineage_witness::tests::witnessed_counts_distinct_independent_witnesses |
| F1 | unwitnessed tail adopted | KILLED | memory::i192, postgres::i192, sqlite::i192 |
| F2 | ever_witnessed exception widened (always unwitnessed = judged at birth) | KILLED | memory_dyn::i190_h, memory_dyn::i190_i, memory_dyn::i190_k, memory_dyn::i190_l, memory_dyn::i190_o, memory_dyn::i190_o3, memory_dyn::i190_o4, memory_dyn::i190_p |
| F3 | equivocation freeze skipped | KILLED | memory::i193, postgres::i193, sqlite::i193 |
| F4 | restore discipline dropped | KILLED | memory::i196, postgres::i196, sqlite::i196 |
| F5 | liveness transition never emitted | KILLED | memory::i195, postgres::i195, sqlite::i195 |
| A1 | stale head attaches | KILLED | memory::i194, postgres::i194, sqlite::i194 |
| A2 | gate never armed | KILLED | memory::i194, postgres::i194, sqlite::i194 |
| A3 | unwitnessed head attaches | KILLED | memory::i194, postgres::i194, sqlite::i194 |
| A4 | any head digest accepted | KILLED | memory::i194, postgres::i194, sqlite::i194 |
| L1 | founding floor at N >= M | KILLED | memory::i195b, postgres::i195b, sqlite::i195b |

Every mutant reverted with `git checkout --` before the next; a `signal: 9` lane is re-run alone (none occurred). Rows marked NOT-APPLIED had a stale pattern and were re-run after the fix (their later row stands).

### 6.2 Review round (PR #943 — the 16 Codex findings, Edge's #923 amendments)

Lane: rc6 + v51 + I190 + lineage_witness + I34b, on memory, sqlite and postgres. Each mutant was applied to a committed tree and reverted before the next.

| # | Mutant | Verdict | Killed by |
|---|---|---|---|
| R1 | witness key validity window unchecked | KILLED | I191 (all backends) |
| R2 | deferred cosign instant not re-checked | KILLED | I197 |
| R3 | fork walk stops at the immediate prior | KILLED | I193b |
| R4 | quorum counts keys, not persons | KILLED | I198, `witnessed_counts_distinct_independent_persons` |
| R5 | witnessed mode engages below the quorum | KILLED | I192b, I198 |
| R6 | a withdrawn owner binding proves ownership | SUPERSEDED | The guard was replaced by the in-force rule (R6b, R11, R12). A granter's own withdrawal retires every later edge from it, so that path cannot return to A. |
| R6b | another owner in force at the row's instant ignored | KILLED | I126 A→B→A |
| R7 | a stalled root is invalid | KILLED | I195 |
| R8 | a stalled root admits members | KILLED | I195 |
| R9 | the charter quorum is not in the standing cache key | KILLED | I192b |
| R10 | restore discipline reads the judged prefix | KILLED | I192b |
| R11 | a lapsed binding stays in force | KILLED | I126 |
| R12 | a withdrawal never ends a binding | KILLED | I126 hand-off |
| R13 | postgres projects a refused duplicate | KILLED | I125b (replication peer set) |
| R14 | the descriptor opener ignores the row's `caller_aad` | KILLED | I122 transplant (sqlite, postgres) |
| R15 | D9: the seal does not widen the chunks | KILLED | I34b (sqlite, postgres) |
| R16 | the window cast wraps | EQUIVALENT | An envelope carries no integer above 2^53 (JCS numbers are doubles), so the cast never wraps. |
| R16b | the window addition is unchecked | KILLED | I194 (2^53 − 1 s window) |

Two first-draft witnesses were measuring a neighbouring fact, and both were rebuilt before their mutant was killed. I125b read the attested column, which the projections never write; it now reads the replication peer set. I194 used a `u64::MAX` window, which canonicalization turns into a float; it now uses 2^53 − 1. A third lane stall came from the harness (`empty_dsn` never reaped) and was fixed there.

## 8. Witnessed mode off (CIRISPersist#973; CC 3.2 T6, operator ruling 2026-10-01)

CC 3.2 T6: "A charter MAY declare `witness_quorum: 0` with no `witnesses[]`: the lineage's **witnessed mode is off**. Then a head counts as current when it carries a valid founder-quorum signature and descends by `prev_head_digest` from a head the consumer holds out of band … and T4a's attach gate reads as *attach only through an out-of-band anchor* (T5): no head is fresh by cosignature, so none is attachable by cosignature." And: "**A charter silent on `witness_quorum` is in witnessed mode off**, exactly as one declaring `0` … a substrate MUST NOT substitute an internal default." And: "A non-zero `witness_quorum` below ⌊n/2⌋ + 1 stays refused."

As built:

- `lineage_witness::declared_witness_quorum` is the one reading of the charter member: absent → `0`. `DEFAULT_WITNESS_QUORUM` is removed. `witnessed()` is false at quorum `0`.
- `witnessed_head` returns "never witnessed" (`judged: None`, no tail, no equivocation) when the mode is off, whatever cosigns are held. The head is the founders' latest admitted version, as before rc6. Cosigns are still admitted and stored by the door as evidence.
- `check_attach_freshness` in off mode: an edge naming the head this node holds attaches (the T5 anchor; the window is not applied, since no cosignature exists to be fresh); an edge naming another head is refused; an edge naming no head is refused when the charter declares a window, and admitted when it declares none (the pre-rc6 edge shape under a pre-rc6 charter, unchanged — the gate re-runs wherever an edge is put, so refusing that shape would refuse edges already in the field).
- `RootWitnessView` gains `held_head`; `quorum` is `0` in off mode.
- Charter admission (`trust_root::check_charter_witness_quorum`, both charter doors) refuses `witness_quorum: 1` naming `charter_witness_quorum_below_majority`.

**In the field.** A lineage whose charter is silent and for which no cosign is held (every lineage in production today) reads the same before and after: it was "never witnessed, judged as before rc6", and it still is. The reading changes only where a silent charter met a held cosign: one cosign used to engage witnessed mode (the default of 1) and no longer does. An anchor attach naming the held head used to be refused as unwitnessed under a silent charter and is now admitted.

### Only a new acceptance edge is gated (T4a, rc6 5cceadb)

The attach gate runs on an edge's FIRST admission. First admission is decided structurally: the edge's id names no row this node holds with the same attester, root and signed envelope. A held edge re-put or replicated back is not re-judged, with or without `attached_head_digest`; it is read as naming the head the node held when it was admitted. A held id offered with a different envelope is a new edge.

A new edge that names itself `trust:accepts:v1` names its head in every mode: the witnessed head while witnessed mode is on, the held (anchored) head while it is off. Without one it is refused `trust_root_head_unnamed`. `attach_head_for(dir, root, now)` returns the head to name.

A row with no job label is not an acceptance edge. See "An unlabelled row" below, which replaces the earlier reading (admitted with no head under a charter with no window, refused under one that declares a window).

### An unlabelled row is no charter and no acceptance edge (T4a, rc6 22ea349, "bundle only")

CC 3.2 T4a: "A new row with no `trust:{job}` label gives no acceptance and is no charter … One exception stands, as a stop-gap until the re-mint: an unlabelled row that is a member of the pinned GenesisBundle (T5, `bundle_fingerprint`) keeps the reading its direction gives it … Unlabelled rows a node already holds keep their reading under T4."

As built:

- **Three ways a `delegates_to` is read by direction.** It names a `trust:{job}` label (the label decides); it is a row of the pinned bundle (`genesis::is_pinned_bundle_row`: baked id, signer, subject, type and canonical envelope all equal); or the node held it when the rule arrived. Every other unlabelled row is stored and stays a delegation for conferral, duties and ownership, and is never a charter or an acceptance edge. `trust_root::direction_denied_ids` is the one place this is decided.
- **Held is a recorded fact.** V167 creates `federation_trust_direction_held` and fills it once, at upgrade, with every unlabelled `delegates_to` in `federation_attestations`. No door writes to it afterwards, so a row put, replicated or imported after the upgrade is new. A signer-chosen instant is not consulted. `trust_direction_held_among(ids)` is the read (all backends, capsule op, directory double).
- **Readers.** `trusted_roots_of`, `trust_root_valid` (edge and charter), `charter_members_for`. `transit_candidate_roots` still enumerates; both of its callers judge each candidate with `trust_root_valid`. Conferral readers are unchanged.
- **The attach gate** returns early for a new unlabelled row outside the bundle: there is no acceptance edge to gate. Bundle rows keep the earlier unlabelled path.
- **The envelope a host writes.** `acceptance_edge_envelope(dir, root, scope, now)` (Engine: `trust_acceptance_envelope`) returns `{"dimension": "trust:accepts:v1", "scope": [...], "attached_head_digest": ...}`.

Consequences to plan for:

- A node that upgrades reads its held unlabelled rows as before. A fresh peer receiving those rows by replication does not. Hosts re-author their acceptance edges labelled, with a head.
- A portable bundle minted before the labels, imported on a fresh node, yields no charter. The shipped bundle is the one exception, by membership.
- The exception ends with the re-mint: once the baked rows carry labels, `is_pinned_bundle_row` has no unlabelled row to match and can be removed.

Witnesses: I366–I371 (CHANGELOG `[53.0.0]`, with the mutation table).

Witnesses: I356 (a new headless edge refused by name in off mode, in witnessed mode, with and without a window; the unlabeled row's reading), I357 (a held headless edge re-put, re-put under a later windowed charter, and replicated back), I358 (a changed envelope under a held id is new), I359 (a new edge naming the held head attaches in off mode).

### A peer does not re-judge another node's attach (T4a)

T4a is "a write-side gate" that "runs on the edge's first admission only"; "once the edge is written, T4 governs without exception". The attaching node's own write is that first admission. `AttachDoor` carries which door an edge arrives through:

| door | origins | what runs |
|---|---|---|
| `Author` | `WriteOrigin::Authored`, the local-tier write | the full gate: the named head is the held (off) or witnessed (on) head, inside the window |
| `Replicated` | `WriteOrigin::Wire`, `WriteOrigin::Sync` | the shape rule only: a new labelled edge names a head |

A peer whose head is ahead of or behind the head an edge names, or that has not witnessed it, admits the replicated edge and reads its author as attached. A node therefore never re-authors its edge because the head advanced. A host writes its own edge through the authored door. Witnesses I372–I375.

### Not yet built

- The witness directory: `witnesses[]` inside the charter, a head's cosignatures judged against its PARENT's directory, and the majority check `witness_quorum = ⌊n/2⌋ + 1` over that directory's size. Until it exists a non-zero quorum counts any registered key typed `witness` that is not a founder's person (§3.2), and only the value `1` is refused at admission. Tracked on CIRISPersist#974.
- Descent from an out-of-band head by `prev_head_digest`: persist's chain is the stored version lineage each put door verified from the accord birth; the `lineage_head` object of CC 3.2 T6 is not a separate stored object.

Invariants I340–I344 (memory, sqlite, postgres): a silent charter is off; an explicit `0` is the same state; off mode attaches by anchor only; an explicit quorum of 2 still witnesses; a quorum of 1 is refused at the charter.

## 9. The community boot leg and the re-bake (CIRISPersist#973)

**Boot leg.** After the delegation plane, boot seeds the baked `ciris-canonical` birth record through the signed `put_community` door (`genesis::seed_canonical_community`). v53.0.0 (CC rc7, T5): the birth is a member of the pinned bundle's `attestations` (after every delegation row, as `{"community": …}`), never a file beside it; `canonical_community_asset()` reads it from the bundle, and a version-2 bundle carries none, so the leg is inert until the final ceremony's bundle is baked.

| state | what the leg does | reported |
|---|---|---|
| no asset baked | nothing: no read, no write | not evaluated |
| id not held | `put_community` (every gate runs) | `Installed`, or `Absent(community)` if the door refuses |
| the baked birth is held | nothing | `AlreadyHeld` |
| a different record is held | nothing; the held record stays | `HeldDiffers` |

The leg's fault is only ever `Absent` (the door refused: a node awaiting its ceremony) or `Unreadable` (the directory could not be asked). It is never `Divergent`, so it cannot stop a boot. `GenesisLeg::Community` is reported by `genesis_posture` once an asset is baked and is not required by `require_constitutional_root`.

**Re-bake on an upgrading node.** The three delegation ids are kept. A re-minted row replaces the stored one only when it is a verifiable holder statement with a STRICTLY newer signed `asserted_at` (#665). Rules the ceremony must follow:
- stamp instants strictly newer than the stored rows: an equal instant with different content is not a successor and the stored row stays;
- do not stamp instants ahead of the fleet's clocks: a row more than 300 s in the future is refused at the write door;
- a third co-scrub is admitted and stored;
- the canonical server record, if unchanged, must be byte-identical (`Unchanged`); if it changes it needs a strictly newer `valid_from`.

The `humanity-accord` family row needs nothing: the seats and the protocol are unchanged.

Witnesses I345–I349 (memory, sqlite, postgres). Not yet built: the software ceremony minter for a dry run, and a boot test over a baked asset (it reads the compiled file).

### 9.1 Posture after a refused or older bake

The boot seed and the live posture leg (`verify_delegation_plane_seeded`, read by `genesis_posture` without the seed) must give one answer for one state. They did not: the leg compared the stored row against the RAW compiled-in row, which is not canonical at rest and so classified as legacy, and every verified holder statement that differed from the bake read as its successor. A node whose re-mint was refused at the door kept reporting `Entrenched` on the previous root.

The rule, by relation of the stored row to the compiled-in one:

- identical, or a verified holder statement strictly newer: sound.
- a verified holder statement that is older, or of the same vintage with different content: **Absent**. The node boots, the banner is raised, and the detail says the compiled-in root was not adopted. Not `Divergent`: that refuses to boot and is reserved for a row that is not a verifiable holder statement.
- an old binary on a newer database (the bake older than stored): the stored rows are never downgraded and the posture is sound.

For the re-mint ceremony this means: a bake stamped ahead of a node's clock by more than the skew bound leaves that node on its previous root, visibly pre-genesis on the delegation leg, until its clock passes the instant and it is rebooted. Witnesses I360–I365.

**The typed reason (requested by CIRISServer).** A host must not read the detail sentence to tell these states apart. `GenesisFault::Absent` and `GenesisPosture::PreGenesis` carry `reason: AbsentReason`:

- `NotSeeded`: the leg is not installed (a node awaiting its ceremony). A posture serialized before the field existed reads as this.
- `BakeNotAdopted { why, held_root_in_force }`: this binary's root was not adopted. `why` is `Refused { refusal }` (the boot seed offered the bake and a door refused it; `refusal` is the error's stable `kind()` token), `StoredOlder` (the live posture: a verified older row is held and the bake is not installed) or `EqualVintage` (a tie). `held_root_in_force` is true when the held row is a verified accord-holder statement, so the previous root still stands.

The boot seed reports `Refused`, because only it sees the refusal. The live posture reports `StoredOlder` or `EqualVintage`, because it sees the rows and not the door. `GenesisPosture::held_root_in_force()` answers the one question a host asks before telling an operator that no trust root is configured, and `banner()` says "ROOT NOT ADOPTED … the previous root stays in force" in that state.

Wire shape (the `state` tokens are unchanged; `reason` is additive):

```json
{"state":"pre_genesis","leg":"delegation","detail":"…",
 "reason":{"kind":"bake_not_adopted","why":{"cause":"stored_older"},"held_root_in_force":true}}
```

`why` is one of `{"cause":"refused","refusal":"<token>"}`, `{"cause":"stored_older"}`, `{"cause":"equal_vintage"}`; a plain pre-ceremony node carries `"reason":{"kind":"not_seeded"}`.

## 10. The dry run: software ceremony, boot seam, outputs verifier (CIRISPersist#973)

**Minter.** `genesis::mint_test_ceremony(ed_seeds[3], node_seed, produced_at)` (feature `test-anchor`) returns the anchor block (unchanged from `mint_test_anchor_block`), the bundle and the `ciris-canonical` birth, signed by the three software holders the block defines. The charter carries `witness_quorum: 0`. A re-mint is the same call with a later `produced_at`: ids kept, instants forward.

**Dry-run order for a host.**
1. Mint (or have the host's own ceremony routes produce the two files with the software holders' seeds).
2. Arm the block (`CIRIS_TEST_TRUST_ROOT*`, `CIRIS_TESTING_MODE=true`).
3. `genesis::install_test_ceremony_outputs_json(bundle_json, Some(community_json))`.
4. Construct the Engine. The boot seed runs anchor → family → serve nodes → delegation plane → community against the installed artifacts; `genesis_posture` reports every leg.
5. `genesis::verify_ceremony_outputs(bundle_json, community_json)` is the same check the real bake will run on the real files.

**The real bake.** Before the ceremony's bundle replaces `canonical_seed.json`, `verify_ceremony_outputs` must return `Ok` on a build whose accord roster is the production one. It applies the bundle — its delegation plane, the accord family record and the birth it carries — through the ordinary doors on an in-memory directory, so a file the boot path would refuse is refused here, by stage.

**Not built:** a pyo3 door for the minter (the block minter has none); a postgres run of I352–I355 (the bodies are backend-generic; the boot, I351, runs on all three).

