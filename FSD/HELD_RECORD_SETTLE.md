# The held-record settle (CIRISPersist#672)

## The problem

Transitive propagation has no hop or TTL bound, so a row could circulate A→B→C→A, and a peer could re-inject rows a node already holds, each re-offer paying the full apply and its quota.

## What bounds it

1. **Pull by set difference.** Replication fetches `want = remote ∖ holdings` (Edge `replication/known_hashes.rs`; persist serves holdings as `list_wire_hashes_since`, #780, and the known-not-held set, #785). An honest cycle re-advertises a row to a node that holds it, the difference drops it, and nothing is fetched.
2. **Monotonic upserts.** A re-applied held row cannot move a serve cursor, so it is never re-advertised.
3. **The settle.** `replication_policy::settle_if_held(dir, kind, record)` runs first in every replicated door, on sqlite and postgres. It serializes the arriving record exactly as the wire index hashes it, looks the hash up, and settles ("already held", no state change) **only** when the entry resolves to a held row whose bytes are identical to the arriving ones. It runs before any signature verify, authority walk or projection, and on the attestation plane before the per-peer write quota, so a held re-offer spends none of the sender's budget. Each settle counts on `already_held_count(kind)` and emits `persist_replication_already_held_total{kind}`.

Everything that is not a byte-identical held row falls through to the full apply, unchanged:
- an index miss;
- an entry whose row is gone (a purged, evicted, erased or reaped row): the lookup reloads the row and returns nothing, so an eviction never masks a re-fetch and an erasure tombstone's refusal is never masked;
- a differing body under a held id: its hash names no held row, so the door refuses or admits it on its merits;
- a backend that cannot answer the lookup.

Exempt kinds, each with its reason in `SETTLE_EXEMPT`: `AccordQuorumEvidence` (an aggregate whose hash moves as votes land, absent from the index by construction; its receive gate re-tallies) and `KeyGrant` (rides the attestation store; a re-delivered set must reach the apply door, which projects a pending set once its bytes name the author).

On every plane, a byte-identical re-offer of a held row is idempotent success (the #771 doctrine for attestations), including planes whose doors would otherwise refuse it (anti-rollback on `scrub_timestamp`, a PK conflict).

Witnesses: I230 (every seeded kind settles, counted), I231 (a differing body and a purged row are not settled), I233 (a three-node cycle returns held), I234 (1 000 held re-offers, over the 600-per-window quota, all settle), I235 (from disk: every replicated door in every backend settles first, under its own kind, or is exempt with a reason).

## What persist does NOT build, and what closes the relay half

No hop counter and no relay-signature chain. A counter outside the signed bytes is forgeable, and one inside them cannot be decremented by a relay; set-difference pull plus the settle bound both the honest cycle and the re-injection.

**Open question (the relay half of #672):** whether any Edge replication path pushes bodies the receiver did not name in its own `want` set. If such a push or flood path exists (for example announce-carried bodies), the settle still bounds its cost to one indexed lookup per held re-offer, and any hop bound belongs in that Edge frame, not in persist's signed rows.
