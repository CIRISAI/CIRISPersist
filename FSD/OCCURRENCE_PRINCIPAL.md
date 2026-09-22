# The principal of an occurrence — resolved, not drawn (CIRISPersist#873)

v45.0.1 (PATCH). Status: normative for persist's occurrence → identity
resolvers and the hold-side audience question. Fixes CIRISPersist#873.

## 1. The shape that broke

Every claimed node carries TWO rows in `federation_identity_occurrences`
for its own key: the boot **singleton** (`identity = node, occurrence =
node`, the row that carries its content-KEM pubkeys) and the owner's
**login anchor** (`identity = human, occurrence = node`, CIRISServer's
`anchor_agent_to_owner`, 0.5.211: the node as an occurrence of the human).
Both are correct by design. Boot precedes claim, so the singleton is always
written first.

`lookup_identity_for_occurrence` was `WHERE occurrence_key_id = ? LIMIT 1`
with no `ORDER BY` on sqlite and postgres, and `.values().find()` over a
HashMap on memory. It returned the singleton (or, on memory, either row,
run to run). `active_identity_for_occurrence` confirmed that row active and
answered **the node**. `audience_memberships` (`replication/hold.rs`, #846)
then asked the roster about the instrument instead of the principal, and
`would_hold` refused every community blob a non-author pulled: `NotPartyTo`
on a room the owner founded. The write side never hit it because
`admission_identity_for_writer` (#765) falls back to `owner_of` when the
occurrence resolves to itself — a guarantee that was not carried to the
hold site.

## 2. The rule (stated once)

**An occurrence's principal is its ACTIVE non-singleton binding.** Among the
rows for `occurrence_key_id`, keep those whose identity's active fold
(`list_identity_occurrences_active`, the #421 re-assert semantics) still
contains this occurrence; of those, the ones with `identity_key_id !=
occurrence_key_id` are the **principals**; the singleton is the fallback
when there is none. A revoked anchor is not active, so the device is its
own key again — the v38.2.0 semantics, unchanged.

**Order is part of the answer.** Principals are ordered newest
`asserted_at` first, then `identity_key_id` ascending. The login anchor is
re-asserted at each login (`self_at_login`), so the newest binding is the
human currently at the keyboard. This is the rule the single-valued
resolver applies; it is deterministic on every backend and identical on
every backend.

## 3. Surface

| symbol | change |
|---|---|
| `FederationDirectory::active_identities_for_occurrence(occ) -> Vec<String>` | NEW, default impl over `list_identity_occurrences_by_occurrence_key` + the active fold; every principal in §2 order; empty when the occurrence has no live non-singleton binding |
| `FederationDirectory::active_identity_for_occurrence(occ) -> String` | now the FIRST of the plural, else `occ` — deterministic; callers unchanged (`admission_identity_for_writer`, the three `Backend::resolve_identity_for_occurrence`s, `audience_memberships`) |
| `FederationDirectory::lookup_identity_for_occurrence(occ)` | keeps its historical-row contract, ordered: non-singleton first, newest `asserted_at`, then `identity_key_id` — `ORDER BY` on sqlite and postgres, a sort on memory. A `LIMIT 1` without an order is the defect class; none remains at this site (from-disk) |
| `replication::hold::audience_memberships(our_key_id)` | unions the active memberships of EVERY principal AND of `our_key_id` itself (a shared device is party to both humans' rooms; the node's own memberships were already included) |
| `admission_identity_for_writer` | unchanged in text; now deterministic by §2. A shared device writes as its newest-anchored human. Not a refusal: the anchor is re-asserted at login, so "newest" is a fact the node itself signed, not a coin toss |

No wire change, no migration, no vocabulary change. PATCH.

## 4. Invariants

- **I121** (3 backends) — singleton then anchor, in that order:
  `active_identity_for_occurrence(node) == owner`;
  `lookup_identity_for_occurrence(node)` is the anchor row. Anchor then
  singleton: the same answers (order of insertion is not the order of
  the answer).
- **I122** (sqlite, postgres) — `would_hold` admits community content of a
  room the owner is an active member of, for a node with both rows;
  `audience_memberships(node)` contains the room.
- **I123** (3 backends) — revoking the anchor (an
  `IdentityOccurrenceRevocation` effective now) returns the node to its
  singleton: the resolver answers the node, `audience_memberships` no longer
  contains the owner's room, and `would_hold` refuses `NotPartyTo` again.
- **I124** (3 backends) — two live anchors (two humans, asserted at
  different instants): the plural lists both, newest first; the single
  resolver answers the newest; `audience_memberships` contains both
  humans' rooms.
- **I125** (from disk) — the `lookup_identity_for_occurrence` bodies in
  sqlite.rs and postgres.rs contain `ORDER BY`; `hold.rs`'s
  `audience_memberships` calls `active_identities_for_occurrence`.

Mutations: drop the non-singleton preference (I121/I122 red); drop the
`ORDER BY` on each backend (I121 red where the singleton was written
first); drop the union (I124 red); drop the active filter (I123 red).

## 5. Not in scope

A refusal for a multi-principal WRITER. Considered and not taken: the
newest login anchor is a signed fact about who is at the keyboard, and a
refusal would brick every shared device's community writes. If a
deployment needs single-principal devices, that is an admission gate on
the anchor plane (a sibling of `check_single_node_owner_admission`), filed
separately if asked.

## 6. The read gate — v46.3.1 (CIRISPersist#888, from CIRISServer#624)

**The shape that broke.** §2 resolved the CALLER: `build_caller_admission`
step 1 answers a claimed node's principal (its owner). The read-side `self`
arm — `CallerScope::admits` (`scope/caller.rs`) and its SQL twin
`cohort_scope_sql_predicate` (`scope/sql.rs`) — kept comparing that resolved
identity to the row's RAW target (`attested_key_id` on memory,
`cohort_target_id` on sqlite/postgres). A node's own `self` rows about itself
(`config:*`, CC 3.4.5 self-or-owner, stamped correctly) became unreadable on
the node that wrote them: `owner == node` is false. Before #873 the singleton
resolved to itself, so raw == resolved and the asymmetry was invisible. Observed
as CIRISServer#624: `GET /v1/config` → `{}`, re-announce 500.

**The rule (stated once).** Both sides of the comparison are resolved the same
way, by the fold `FSD/SELF_COLLECTIVE_TRANSFER.md` §4.1 already names:

```
admits(self, target) := target ∈ self_key_ids(caller)
self_key_ids(caller) := {caller, identity(caller)}
                      ∪ P ∪ ⋃_{p ∈ P} (active occurrences of p ∪ nodes_owned_by(p))
where P := principals_of(caller) ∪ {identity(caller)}
```
— the caller's self-collective (CC 3.3.6; CC 5.2 `recipients := all current
identity_occurrences of C.attesting_key_id`), built by the substrate inside
`build_caller_admission_from_directory` (AV-44: never caller-asserted; the
seal stays). The SQL twin binds the same set (`IN` / `= ANY`), exactly as the
family and community arms already do. The write-side assembler
(`CallerAdmission::from_resolved`, the trace-ingest pipeline) carries
`{occurrence, identity}` — it never evaluates the self read arm.

| symbol | change |
|---|---|
| `CallerAdmission::self_key_ids` | NEW, sealed; the caller's self-collective as key ids |
| `CallerScope::admits` `"self"` arm | `target ∈ self_key_ids` (was `target == identity_key_id`) |
| `cohort_scope_sql_predicate` `self` branch | `target_membership_branch(.., "self", self_key_ids, ..)` (was `= $identity`) |
| `self_collective::occurrences_of`, `nodes_of` | `pub(crate)`, generic over an unsized directory — the folds the admission builder reads |
| `self_collective::principals_of` | a REVOKED occurrence does not inherit its owner through a live owner binding (PR #889 review P1): `k` bound to `owner` at some time and not active now ⇒ `owner ∉ principals_of(k)`. One fold, so `speaks_for`, the send set and the read gate all say it |
| `CallerScope::admits(cohort_scope, target, dimension)` | takes the row's dimension: a `CONFIG_SENSITIVE_LEAVES` leaf (CC 3.4.5.1, node-local by the write floor) is admitted at `self` only when `target == occurrence_key_id` (PR #889 review P1) |
| `cohort_scope_sql_predicate_with_dimension` / `scope_predicate_{pg,sqlite}_with_dimension` | the same node-only clause in SQL, rendered with `substr`/`length` (no `LIKE`: its case rule differs by backend); composed by every door over `federation_attestations` — the only tables carrying `config:*` rows — pinned from disk |
| `CallerScope::admits_local_tier(tier, attesting_key_id)` / `local_tier_sql_predicate` | NEW (PR #889 review, round three): a `local`-tier row (V4.4 §3, producer-only authority) is visible to its producing OCCURRENCE alone — `tier <> 'local' OR attester = occurrence`; the collective widening never reaches it. Composed by the same six attestation doors; pinned from disk |
| `cache::key::scope_digest` | folds the occurrence and `self_key_ids` (domain tag `CallerScope:v46.3.1`): two admissions differing only in the collective, or in the occurrence, never share an aggregate cache entry (PR #889 review, round three) |

No wire change, no migration, no vocabulary change. PATCH.

**Invariants.**
- **I141** (3 backends, Rust twin; sqlite + postgres also through
  `ReadEngine::list_attestations`, the SQL twin) — a claimed node (owner
  binding + occurrence) writes two `self` rows about itself (`config:*`);
  the node reads both; the owner's key reads both; the owner's second device
  reads both (CC 5.2); a node the owner OWNS but never bound as an occurrence
  reads both; the node reads what the device and the owned-only node write
  about themselves; a stranger node reads none. The node's `config:admission`
  leaf is read by the node alone — not the device, not the owner's key, not
  the other node. After the owner REVOKES the node's occurrence (owner
  binding kept): the node reads only its own rows, `speaks_for(node, owner)`
  is false, the device still reads the (owned) node's plain rows. A
  `local`-tier row the node wrote through the local door is read by the node
  alone — not the device, not the owner, not the other node. Unclaimed
  (singleton) the node still reads its own.
- Mutants: self set = `{identity}` only (node red); drop the occurrence union
  (the DEVICE's own row unread — every reader in the first draft was also an
  owned node, so only a writer that owns no node exercises this fold); drop
  `nodes_owned_by` (the owned-only node's own row unread — the mirror gap);
  SQL branch back to `= identity` (sqlite red); `admits(self) → true`
  (stranger red); `principals_of` ignores the revocation (revoked node reads
  the device's row); drop the sensitive clause in the Rust twin (device reads
  the leaf, memory/sqlite); drop it in the SQL twin (sqlite); drop the SQL
  twin's `dimension IS NULL` (review round two: `dimension` is a GENERATED
  column, NULL for every attestation type without a dimension member, and
  `NOT (NULL)` is NULL — the shape test pins the clause on both backends).
  Round three: `admits_local_tier → true` (device reads the local row,
  memory/sqlite); the SQL local-tier clause dropped (sqlite); the scope
  digest drops the self set (the `cache::key` test's `wider` /
  `other_device` digests collide).

### 6.1 Mutation table (sqlite lane, 2026-09-22; rounds a–c)

| Mutant | Verdict |
|---|---|
| M1 self set = {identity} only | KILLED by memory::i141 sqlite::i141  |
| M4 SQL self branch back to = identity | KILLED by sqlite::i141  |
| M5 admits(self) = true | KILLED by memory::i141 sqlite::i141  |
| M2 drop the occurrence union | KILLED by memory::i141 sqlite::i141  |
| M3 drop nodes_owned_by | KILLED by memory::i141 sqlite::i141  |
| M6 principals_of ignores the revocation | KILLED by memory::i141 sqlite::i141  |
| M7 Rust twin drops the sensitive clause | KILLED by memory::i141 sqlite::i141  |
| M8 SQL twin drops the sensitive clause | KILLED by sqlite::i141  |
