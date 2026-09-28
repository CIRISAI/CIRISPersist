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
- `witness_quorum: u32` (optional, default 1) — how many independent witnesses make a head "witnessed". The rulings say "the witness quorum" without a number; persist's default is ONE independent witness, charter-overridable, stated here so it is not re-asked.

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
- Residual: `witness_quorum` default 1 is persist's choice pending CC text; a charter may raise it.
