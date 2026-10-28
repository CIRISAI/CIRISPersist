# The principal of an occurrence — resolved, not drawn (CIRISPersist#873)

Status: normative for persist's occurrence → identity resolvers, the
hold-side audience question, and the `self` read gate. Tracking:
CIRISPersist#873, CIRISPersist#888.

## 1. Two rows for one key

Every claimed node carries TWO rows in `federation_identity_occurrences`
for its own key: the boot **singleton** (`identity = node, occurrence =
node`, the row that carries its content-KEM pubkeys) and the owner's
**login anchor** (`identity = human, occurrence = node`, CIRISServer's
`anchor_agent_to_owner`: the node as an occurrence of the human). Both are
correct by design. Boot precedes claim, so the singleton is always written
first.

A resolver that picked one row for the occurrence (`LIMIT 1` with no
`ORDER BY`) would return the singleton and answer **the node**.
`audience_memberships` (`replication/hold.rs`, #846) would then ask the
roster about the instrument instead of the principal, and `would_hold`
would refuse every community blob a non-author pulled: `NotPartyTo` on a
room the owner founded. The write side resolves the same way:
`admission_identity_for_writer` (#765) falls back to `owner_of` when the
occurrence resolves to itself. §2 is the one rule both sides read.

## 2. The rule (stated once)

**An occurrence's principal is its ACTIVE non-singleton binding.** Among the
rows for `occurrence_key_id`, keep those whose identity's active fold
(`list_identity_occurrences_active`, the #421 re-assert semantics) still
contains this occurrence; of those, the ones with `identity_key_id !=
occurrence_key_id` are the **principals**; the singleton is the fallback
when there is none. A revoked anchor is not active, so the device is its
own key again.

**Order is part of the answer.** Principals are ordered newest
`asserted_at` first, then `identity_key_id` ascending. The login anchor is
re-asserted at each login (`self_at_login`), so the newest binding is the
human currently at the keyboard. This is the rule the single-valued
resolver applies; it is deterministic and identical on both backends.

## 3. Surface

| symbol | meaning |
|---|---|
| `FederationDirectory::active_identities_for_occurrence(occ) -> Vec<String>` | default impl over `list_identity_occurrences_by_occurrence_key` + the active fold; every principal in §2 order; empty when the occurrence has no live non-singleton binding |
| `FederationDirectory::active_identity_for_occurrence(occ) -> String` | the FIRST of the plural, else `occ` — deterministic; read by `admission_identity_for_writer`, `Backend::resolve_identity_for_occurrence`, `audience_memberships` |
| `FederationDirectory::lookup_identity_for_occurrence(occ)` | the historical-row contract, ordered: non-singleton first, newest `asserted_at`, then `identity_key_id` — `ORDER BY` on sqlite and postgres. A `LIMIT 1` without an order is the defect class; I125 pins its absence at this site from disk |
| `replication::hold::audience_memberships(our_key_id)` | unions the active memberships of EVERY principal AND of `our_key_id` itself (a shared device is party to both humans' rooms, and to the node's own) |
| `admission_identity_for_writer` | deterministic by §2. A shared device writes as its newest-anchored human. Not a refusal: the anchor is re-asserted at login, so "newest" is a fact the node itself signed, not a coin toss |

## 4. Invariants

- **I121** (sqlite, postgres) — singleton then anchor, in that order:
  `active_identity_for_occurrence(node) == owner`;
  `lookup_identity_for_occurrence(node)` is the anchor row. Anchor then
  singleton: the same answers (order of insertion is not the order of
  the answer).
- **I122** (sqlite, postgres) — `would_hold` admits community content of a
  room the owner is an active member of, for a node with both rows;
  `audience_memberships(node)` contains the room.
- **I123** (sqlite, postgres) — revoking the anchor (an
  `IdentityOccurrenceRevocation` effective now) returns the node to its
  singleton: the resolver answers the node, `audience_memberships` no longer
  contains the owner's room, and `would_hold` refuses `NotPartyTo` again.
- **I124** (sqlite, postgres) — two live anchors (two humans, asserted at
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

A refusal for a multi-principal WRITER. The newest login anchor is a signed
fact about who is at the keyboard, and a refusal would brick every shared
device's community writes. A deployment that needs single-principal devices
would need an admission gate on the anchor plane (a sibling of
`check_single_node_owner_admission`); none exists.

## 6. The read gate (CIRISPersist#888, from CIRISServer#624)

**Why both sides resolve.** §2 resolves the CALLER: `build_caller_admission`
step 1 answers a claimed node's principal (its owner). The read-side `self`
arm — `CallerScope::admits` (`scope/caller.rs`) and its SQL twin
`cohort_scope_sql_predicate` (`scope/sql.rs`) — compares against the row's
target (`cohort_target_id`). Comparing the resolved identity to the RAW
target would make a node's own `self` rows about itself (`config:*`, CC 3.4.5
self-or-owner) unreadable on the node that wrote them, because `owner == node`
is false (CIRISServer#624: `GET /v1/config` → `{}`).

**The rule.** Both sides of the comparison are resolved the same
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
admission is sealed). The SQL twin binds the same set (`IN` / `= ANY`), exactly
as the family and community arms do. The write-side assembler
(`CallerAdmission::from_resolved`, the trace-ingest pipeline) carries
`{occurrence, identity}` — it never evaluates the self read arm.

| symbol | meaning |
|---|---|
| `CallerAdmission::self_key_ids` | sealed; the caller's self-collective as key ids |
| `CallerScope::admits` `"self"` arm | `target ∈ self_key_ids` |
| `cohort_scope_sql_predicate` `self` branch | `target_membership_branch(.., "self", self_key_ids, ..)` |
| `self_collective::occurrences_of`, `nodes_of` | `pub(crate)`, generic over an unsized directory — the folds the admission builder reads |
| `self_collective::principals_of` | a REVOKED occurrence does not inherit its owner through a live owner binding: `k` bound to `owner` at some time and not active now ⇒ `owner ∉ principals_of(k)`. One fold, so `speaks_for`, the send set and the read gate all say it |
| `CallerScope::admits(cohort_scope, target, dimension)` | takes the row's dimension: a `CONFIG_SENSITIVE_LEAVES` leaf (CC 3.4.5.1, node-local by the write floor) is admitted at `self` only when `target == occurrence_key_id` |
| `cohort_scope_sql_predicate_with_dimension` / `scope_predicate_{pg,sqlite}_with_dimension` | the same node-only clause in SQL, rendered with `substr`/`length` (no `LIKE`: its case rule differs by backend); composed by every door over `federation_attestations` — the only tables carrying `config:*` rows — pinned from disk |
| `CallerScope::admits_local_tier(tier, attesting_key_id)` / `local_tier_sql_predicate` | a `local`-tier row (V4.4 §3, producer-only authority) is visible to its producing OCCURRENCE alone — `tier <> 'local' OR attester = occurrence`; the collective widening never reaches it. Composed by the same six attestation doors; pinned from disk |
| `cache::key::scope_digest` | folds the occurrence and `self_key_ids` (domain tag `CallerScope:v46.3.1`): two admissions differing only in the collective, or in the occurrence, never share an aggregate cache entry |

**Invariants.**
- **I141** (sqlite, postgres — the Rust twin, and also through
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
  (the DEVICE's own row unread — only a writer that owns no node exercises
  this fold); drop
  `nodes_owned_by` (the owned-only node's own row unread — the mirror gap);
  SQL branch back to `= identity` (sqlite red); `admits(self) → true`
  (stranger red); `principals_of` ignores the revocation (revoked node reads
  the device's row); drop the sensitive clause in the Rust twin (device reads
  the leaf); drop it in the SQL twin (sqlite); drop the SQL twin's
  `dimension IS NULL` (`dimension` is a GENERATED column, NULL for every
  attestation type without a dimension member, and `NOT (NULL)` is NULL —
  the shape test pins the clause on both backends); `admits_local_tier →
  true` (device reads the local row); the SQL local-tier clause dropped
  (sqlite); the scope
  digest drops the self set (the `cache::key` test's `wider` /
  `other_device` digests collide).

### 6.1 Mutation table (sqlite lane; 12/12 killed)

| Mutant | Verdict |
|---|---|
| M1 self set = {identity} only | KILLED by sqlite::i141  |
| M4 SQL self branch back to = identity | KILLED by sqlite::i141  |
| M5 admits(self) = true | KILLED by sqlite::i141  |
| M2 drop the occurrence union | KILLED by sqlite::i141  |
| M3 drop nodes_owned_by | KILLED by sqlite::i141  |
| M6 principals_of ignores the revocation | KILLED by sqlite::i141  |
| M7 Rust twin drops the sensitive clause | KILLED by sqlite::i141  |
| M8 SQL twin drops the sensitive clause | KILLED by sqlite::i141  |
| M9 SQL twin drops `dimension IS NULL` (NOT (NULL) hides dimension-less rows) | KILLED by sql::with_dimension_keeps_sensitive_leaves_node_only_both_backends  |
| M10 admits_local_tier = true (local rows leak to the collective, Rust twin) | KILLED by sqlite::i141  |
| M11 SQL local-tier clause dropped | KILLED by sqlite::i141  |
| M12 scope digest drops the self set and the occurrence | KILLED by key::scope_digest_is_set_order_invariant  |
