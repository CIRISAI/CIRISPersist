# FSD — the promotion sweep sees a claimed machine's consent (CIRISPersist#905)

**Problem it solves:** a claimed machine (an owned agent) whose owner authored `consent:replication:v1` toward a peer (`for_key_id` = the machine) must have its sealed traces promoted by that consent. A sweep that loads only grants the machine itself authored loads none, and the machine's traces stay `(self, local)` with no refusal.

## 1. The shape of consent for a claimed machine
- The grants that cover a machine are authored by its HUMAN and name the machine in `for_key_id` (#857, V147); `consent_peers_by_principals(k)` folds them for peers.
- The promotion sweep (`Engine::load_active_egress_grants`, the front half of `promote_consented_backlog` and `repair_stranded_scope_backlog`) and the crossing's covering check (`crossing::check_grant_covers`) must therefore both accept a grant the machine's steward authored for it, not only one the machine authored.
- `consent_peer_set` must keep a human's two per-key grants toward one peer apart, so that withdrawing one does not drop the peer while the other stands.

## 2. The rule
**Whose consent covers a producer is one question with one answer, by principals:** the producer's own grant, or a grant its bound steward authored naming it. Every door that asks — the sweep's loader, the crossing's covering check — asks the same predicate.

## 3. The structure
- `consent_by_humans::grant_is_authored_for(dir, grant, machine)`: `grant.attesting_key_id == machine` ∨ (`for_key_id_of(grant) == machine` ∧ `grant.attesting_key_id ∈ steward_bindings_of(machine)`).
- `consent_by_humans::live_egress_grants_by_principals(dir, k)` = `list_live_consent_grants_by(k)` ∪ {g ∈ `list_live_consent_grants_for(k)` : `grant_is_authored_for(g, k)`}, deduped, newest first. New trait read `list_live_consent_grants_for(for_key_id)` (the V147 projection's live sources) on sqlite and postgres.
- `Engine::load_active_egress_grants` loads by principals; `crossing::check_grant_covers` accepts by the predicate.
- **V152**: `consent_peer_set` gains `for_key_id` in its key `(node_key_id, for_key_id, peer_key_id)`; a self-grant is keyed on its author (the pre-#857 shape). Backfilled from the source attestation's envelope. `list_consent_peers` (DISTINCT) and the by-source deletes keep their meaning.

## 4. Invariants
- **I168 — an owned agent's sealed traces are promoted by its human's consent** (sqlite, on an `Engine`): the machine registers itself, its owner is bound to it, a sealed local trace is authored by the machine, the OWNER's grant names the machine and the machine authored none. Control: no grant → `promoted = 0`. Then `promote_consented_backlog` → `promoted = 1`, the row at the federation tier; a second sweep → 0. The witness captures the sweep's log lines into its own assertion, so a skip names itself.
- **I169 — a human's two per-key grants toward one peer are both live** (sqlite + postgres): both in `list_live_consent_grants_by(human)`; the peer once in `list_consent_peers(human)`; by principals each machine sees exactly the grant naming it; an unbound author's grant naming the machine is not the machine's; withdrawing the actor's grant leaves the node's grant live and the peer still the human's peer.

## 5. Verification

Mutation: the predicate's steward arm and its `for_key_id` check, the loader's by-for union, `list_live_consent_grants_for`'s `for_key_id` filter, and the crossing's covering check are each killed by I169 (and the loader and steward arm by I168). The reader and the predicate are asserted directly, not only through the loader, because on the loader path each masks a mutant of the other.

## 6. Not in scope
CIRISServer's own `live_consent_grants_for_machine` reader (it goes through `list_live_consent_grants_by`, which V152 makes agree with the by-principals fold — no persist API change for it); retroactive re-promotion of rows already skipped (the next sweep picks them up: `(local, self)` rows are re-read every run).
