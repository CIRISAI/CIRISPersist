# Self/family bytes are delivered, not discovered (CIRISPersist#884)

v46.3.0. Status: normative for persist's half of the self/family transfer plane.
The cross-repo state table is CIRISEdge's `FSD/CONTENT_TRANSFER.md` §5.3; this
document is persist's row set for it, rung by rung, and cross-links by rung id.

## 1. The ruling, restated exactly once

CC 5.2 (`part_5_transport_substrate.md`): *"the substrate MUST NOT emit a
corresponding `holds_bytes:sha256:{prefix}` directory attestation … the
content's bytes are delivered to admitted members of the relevant
self-collective (CC 3.3.6 `identity_occurrence`) or family (CC 3.3.4) via the
at-rest encryption flow, NOT via the public holder-discovery directory."*
Unconditional. Persist emits no holder claim at any audience (I52 stands);
the bytes move by fan-out from the node that sealed them.

## 2. The objects, as persist names them

| object | persist's name | authority |
|---|---|---|
| the row | `Attestation` at `cohort_scope = self \| family` | the access grant (`is_audience`, the `self` arm: principal equality) |
| the citation | `evidence_refs[]` (CIRISEdge#646) | the relation `attestations_binding_content` indexes |
| the pointer | `blob_pointer::pointer_for` | the key plane (tier, community, epoch) — v46.1.0 |
| the key set | `key_grant:content:v1` (self/family) / `key_grant:epoch:v1` (community) | the MINTER: its attester sealed the bytes |
| the self-collective | `list_identity_occurrences_active(principal)` | membership is a cryptographic fact (CC 3.3.6), never a consent row |

## 3. Persist's rungs (edge §5.3 ids)

| rung | persist primitive | before v46.3.0 | witness |
|---|---|---|---|
| R0 | `put_blob_scoped` self branch: per-write DEK wrapped to every active occurrence; no claim | ✓ | I52 |
| **R2** | **`send_set_for(k, scope)`** — consent peers ∪ the self-collective (∪ family members' collectives for `family`) | persist only classified `OwnRoster`; the resolver was grants-only; a self row reached no second device | **I137** |
| **R3-retro** | `rekey_self_occurrence_add` / `rekey_family_member_add` (v6.1.0) emit the full content set for the newcomer; fired by `self_at_login`; **now on PyO3** | existed; sets projected `SelfOwn` into an empty send set (R2) | **I138** |
| **R4** | **`minter_of_blob(sha)`** — community: the epoch binding's minter; self/family: the content set's attester. Edge's self/family source rule is the author's nodes (§6.2) — this read is symmetry, not a gate | community half existed (#876); no content-axis read | **I139** |
| **R7** | `would_hold` / `is_audience` self+family arm by PRINCIPAL (`speaks_for(our_key, author)`, §4.1); adopt `LocalOnly` | #873 lifted only the community memberships — a person-authored `self` row was `NotPartyTo` on the person's own second node | **I138** (I135 stays) |
| — | PyO3 exposure of the three (from disk) | — | **I140** |

## 4. `send_set_for` — the rule

```
send_set_for(k, scope):
  base := consent_peers_by_principals(k)                       # unchanged consent fact
  if scope ∈ {self, family}:
      principals := principals_of(k)                           # §4.1: active_identities_for_occurrence(k)
                                                               # ∪ owner_of(k) ∪ {k if user-role}
      base ∪= ⋃ nodes_owned_by(p)  for p in principals         # NODES, never occurrence keys
  if scope == family:
      base ∪= ⋃ nodes_owned_by(m) for every active member m of every family p is an active member of
  base \ {k}, sorted, deduped
```
A `community` / `affiliations` / commons scope returns `base` unchanged — those
planes are `Cohort` / `Global` projected and their audience is the roster, not
the collective.

**Nodes, not occurrences** (edge `FSD/CONTENT_TRANSFER.md` §6.1, CC
4.4.3.2.4.1(b)). An occurrence is a content-KEM target (CC 3.3.6.1), not a
replication endpoint: a device-class occurrence has no destination, and under
`use_node_identity` (CIRISEdge#541) an actor occurrence's key is not the key
peers see. The consent half is already in node key ids; the collective half
is the same shape. Operator ruling (#884): *a node always has exactly one
human owner, and what a node seals is the human's* — so the occurrence → node
step on persist's side is `nodes_owned_by(principal)`, the owner-binding fold
(`n ∈ nodes_owned_by(U) ⟺ owner_of(n) == U`), over `principals_of(k)` (§4.1).

### 4.1 `speaks_for(signer, author)` — the key plane's voice

A content-axis `key_grant` set is signed by the node that SEALED the bytes
(`Engine::emit_key_grant` → `emit_attestation_self`, the node's derived key).
A chat row is authored by a PERSON, or by their actor occurrence. v46.0.0
split author from sealer on the epoch axis (`FSD/EPOCH_MINTER.md`); the
content axis kept `signer == author` at all three sites (`key_grant.rs`
admission, its race double-check, `project_pending_content_grants`), so a
person-authored self blob's set was **retired as "not the author" on every
second device** — silently, at the adopt's pending projection. That is the
defect under edge §6.2's premise ("on the content axis the minter is the
author"): true on the sealing node, where the door records the node as the
author; false on the receiving node, which records the row's attester.

```
speaks_for(signer, author) := signer == author
                            ∨ principals_of(signer) ∩ principals_of(author) ≠ ∅
```
`principals_of(k)` = the identities `k` is an active occurrence of (#873) ∪
`owner_of(k)` ∪ {`k` if user-role} — one generic fold, read by the send set,
the key gate, and the hold path's self/family arm (`is_audience`): the two
keys share a human. A revoked occurrence with no live owner binding shares none (a lost
device that still knows a DEK cannot grant an outsider — I65's forger is now
exactly that); a family member's node shares none. `minter_of_blob` is NOT on
this gate: for self/family it is a read of what the set's attester signed, kept
for the community source rule's symmetry (R4), not load-bearing here.

## 5. Invariants — and the mutant each must kill

- **I137** — `send_set_for(A_node, self)` on a node whose owner owns a second
  node B contains B with NO consent row between them; contains the consent
  peers too; does not contain A itself, the owner's key, or an occurrence
  that owns no node (a phone); `send_set_for(A_node, community)` equals
  `consent_peers_by_principals(A_node)`; for `family`, a family member's node
  is included, for `self` it is not. Mutants: drop the node union (self red);
  union occurrences instead of nodes (phone red); apply it at community
  (community red); include family nodes at self (self red).
- **I138** — two NODE engines, owner-bound and occurrence-bound to the same
  human on both directories: seal a self blob on A while A is the only
  occurrence; admit B after; `send_set_for(A, self)` names B;
  `rekey_self_occurrence_add` on A grants B; A's content sets (write + re-key,
  signed by NODE A) reach B BEFORE the bytes — admitted, pending, nothing
  projected; the bytes adopted `LocalOnly` on B with the row's author (the
  human); `read_blob_as(B)` OPENS; a set signed by a stranger is refused
  `signer_not_author` by name. Mutants: `speaks_for → signer == author` (B
  `NotGranted`); `speaks_for → true` (stranger admitted; I65's revoked
  device projects); the re-key emits no set.
- **I65** (existing, re-cast) — the forger is the owner's REVOKED device.
- **I139** — `minter_of_blob(sha)` is the node key for a community blob and
  the content set's attester for a self blob; `None` for an unknown sha.
  Mutant: the self arm returns the row's author (a person) instead of the
  set's attester.
- **I140** — from disk: the three PyO3 doors exist and are classified.

## 6. Not in scope

Push-on-write (`deliverables_for_occurrence`): an optimisation once the pull
floor has a witness on edge. Any holder claim at any scope. The self room
(edge §6.3) and the drive (server).
