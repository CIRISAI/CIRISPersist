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
| **R4** | **`minter_of_blob(sha)`** — community: the epoch binding's minter; self/family: the content set's attester | community half existed (#876); no content-axis read | **I139** |
| R7 | `would_hold` self arm (principal equality, #873); adopt `LocalOnly` | ✓ | I135 |
| — | PyO3 exposure of the three (from disk) | — | **I140** |

## 4. `send_set_for` — the rule

```
send_set_for(k, scope):
  base := consent_peers_by_principals(k)                       # unchanged consent fact
  if scope ∈ {self, family}:
      principals := active_identities_for_occurrence(k) ∪ {k if k is an identity with occurrences}
      base ∪= ⋃ list_identity_occurrences_active(p).occurrence_key_id  for p in principals
  if scope == family:
      base ∪= ⋃ occurrences of every active member m of every family p is an active member of
  base \ {k}, sorted, deduped
```
A `community` / `affiliations` / commons scope returns `base` unchanged — those
planes are `Cohort` / `Global` projected and their audience is the roster, not
the collective.

## 5. Invariants — and the mutant each must kill

- **I137** — `send_set_for(A_node, self)` on a node whose owner has a second
  occurrence B contains B with NO consent row between them; contains the
  consent peers too; does not contain A itself; `send_set_for(A_node,
  community)` equals `consent_peers_by_principals(A_node)`; for `family`,
  a family member's device is included, for `self` it is not. Mutants: drop
  the occurrence union (self red); apply it at community (community red);
  include family collectives at self (self red).
- **I138** — two engines: seal a self blob on A while A is the only
  occurrence; admit B as an occurrence of A's owner; `rekey_self_occurrence_add`
  on A emits a content set naming B; carried to B and admitted; the bytes
  adopted `LocalOnly` on B; `read_blob_as(B)` OPENS. Mutant: the re-key
  emits no set (B `NotGranted`).
- **I139** — `minter_of_blob(sha)` is the node key for a community blob and
  the content set's attester for a self blob; `None` for an unknown sha.
  Mutant: the self arm returns the row's author (a person) instead of the
  set's attester.
- **I140** — from disk: the three PyO3 doors exist and are classified.

## 6. Not in scope

Push-on-write (`deliverables_for_occurrence`): an optimisation once the pull
floor has a witness on edge. Any holder claim at any scope. The self room
(edge §6.3) and the drive (server).
