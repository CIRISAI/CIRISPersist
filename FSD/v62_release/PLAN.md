# v62 plan: finishing on the kernel release

## Strategy

Delete the superseded rule code wholesale and prove the result with the
suites and benchmarks, instead of porting it fold by fold. Reasons:

- The old folds and the crate do not ask the same question. The old folds
  read a roster "at an instant"; the crate reads the rows in a row's own
  past. A function-by-function differential would report differences that
  are the intended change.
- No compatibility with earlier row forms is owed, so the earlier-form doors
  have no replacement to port to.
- The comparison that means something is at the level a host sees: the same
  scenario, driven through the doors, before and after.

So "A/B" here means:

| A (before) | B (after) | Compared by |
|---|---|---|
| The build line at the base of this branch | The branch after the swap | Host-level scenario suites and two-node witnesses that deliver through the planes, on sqlite and postgres |
| same | same | The benchmark set, interleaved A/B rounds, never a blocked run |
| The kernel's own expected answers | Persist's presentation | Kernel's vector set replayed through persist's door on both backends |

A scenario whose expected outcome changes because the rule changed is
rewritten against the crate's answer and the change is listed in the
adoption notes. A scenario that only asserted an old fold's internals goes
with the fold.

## Order of work (starts when the kernel tag exists)

1. **Baseline.** Record the scenario inventory and the benchmark numbers at
   the branch base, before anything is deleted.
2. **Pins and generated files.** Constitution pre-release tag, Verify, kernel
   0.5.0. Regenerate the family model, vocabulary and policy pin by script.
   Adopt Verify's breaking changes.
3. **Presentation.** Rewrite `src/kernel/` from the kernel's wire map: one
   function from a stored statement to the crate's row view, nothing
   synthesised, no policy table. Replay the vector set on both backends.
   This is the only new rule-adjacent code, and the vectors pin it.
4. **Delete by list.** `DELETE_LIST.md`, in this order: earlier-form doors
   and their tables; the roster replay and everything that reads "the roster
   at an instant"; counts and thresholds; objections and two-path; persons;
   heads; trust root; key plane; delegation and duties; audience and
   serving; purge, quarantine. Each deletion takes its tests and its entry
   in the from-disk gates with it.
5. **Doors ask the crate.** Each door presents the row and its past, stores
   the answer's named row when the answer is undecided, and asks again when
   that row lands. The fold scheduler stays as that loop. No verdict is
   stored; nothing is pruned in this release.
6. **Stores.** Remove verdict-bearing projections and columns on both
   backends (schema edited in place; this release starts a new mesh).
7. **New storage and production** (not rules): shapes and producers for
   election, duty, window, regard and room-node rows; room keys and wraps
   driven by the crate's audience answer; the serve path driven by the
   crate's placement answer; node routing stays persist's.
8. **Host surface.** `HOST_VERBS.md`; every change approved by Eric; adoption
   notes for Edge and Server.
9. **Shut doors.** Each feature in "shut in v62" refuses or holds with a
   token given by the Constitution repo.
10. **Proof.** Witnesses on both backends, mutation of the witnesses,
    evidence manifest by the claim-id delta, the certify lanes, then the tag.

## Boundary: what the kernel release answers

From Kernel's audit of persist's list, relayed 2026-11-27. Function names
are the crate's; some were still being merged. `KERNEL_MAP.md` checks each
against the branch.

**In 0.5.0**

- Roster at heads, counts, protocol and policy per act, founders,
  infrastructure rules, families.
- Growth needs the member's reply; withdrawal of an offer or acceptance;
  proposal expiry at a caller-stated instant; election decline.
- Objections and windows as rows; the lone act after a silent window.
- Holds: an act is held as a proposal until a countersign naming it
  concludes. No expiry.
- Persons: a person's keys as one voice, read at a row (being built).
- Rotation chain, rival rotations, who may revoke, suspect statements.
- Delegation walk and terms, steward and owner bindings, moderators, duty
  holders, slash / quarantine / takedown acts in force, licensure reach,
  elections.
- The trust root's fork fold, joins, grants and charter coverage; accord
  m-of-n; the halt count.
- The affiliation's lone-officer countersign (being built).
- Who is served, for rows: placement and audience for every family.
- Quarantine fold; takedown and reconsideration standing.
- Settled by receipts, in the crate's store model.

**Not the crate's**

- Signature, location-proof and receipt-signature validity: Verify.
- Which nodes a key's rows are routed to: persist.
- One row against the clock (future-dated skew, a nonce's age): persist's
  door.
- The halt latch and its fuse: the node's own clock.

**Not in this tag**

| Item | Persist's reading | Effect if shut |
|---|---|---|
| Minor rule and the age band | Must have (Kernel: sized for 0.5.1) | Either every duty edge waits for an age answer or minors are unprotected. Eric's choice. |
| Replication audience | Being built for 0.5.0: `audience::audiences`, `seat::person_keys`, `standing::nodes_of`, each at a row | Cannot be shut: nothing replicates |
| Consent peer set | Must have (Edge depends on it). Kernel: now in 0.5.0 | Cannot be shut |
| `admission:unit` and the receipts' trusted-service rule | Shut. Edge does not use it; the agent fails closed for units beyond its attested build and keeps running | Nothing beyond the attested build loads. Same function name and row shape when it returns |
| Steward purge as a counted act | Likely in 0.5.0: needs one acts-table row and an arm | none if it lands |
| Invitation decline | Shut | A declined invitation stays unanswered until it expires or is withdrawn |
| Pending invitees as a query | Not needed: the invitation row names its invitee | none |
| One-proposer invitation window | Shut | none at the pin |
| Dismissals and the steward tier of an objection | Deleted | Outcome is the count and the window's landing |
| Expiry of holds | Deleted | A short count's voices are kept |
| Occurrence withdrawal | Shut: the door refuses it | A device is removed by eviction or its key's end |
| Geographic charter class | Shut | Such a record is refused |
| Ownership reclaim by abandonment | Shut | An abandoned node stays bound; the owner's own withdrawal works |
| `mesh_config` fold and quorum | Shut | Configuration is what the release bakes |
| Finality over seat, content and window rows | Keep every row | Storage grows; nothing is pruned |
| "Strictly wider" crossing check | Core stays: one row against the row it names, no instant | none |

## Open questions

With Kernel (yes or no each): the three-answer composition for the
replication audience; the default fold for the consent peer set; what
steward purge lacks; that placement serves an invitation to the key it
names.

With the Constitution session: whether the steward tier of an objection
survives in the text; the tokens for each shut door.

With Eric: the shut list above; the choice on the minor rule until 0.5.1;
every host-verb change.
