# v62 release log

Marks: READ = read in code or text; CHECKED = run; BELIEVED = inferred.

## 2026-11-27

- The main checkout and the untracked working log of the v62 program were
  lost when old directories were cleaned. The 55 surviving lane worktrees
  were pushed as `rescue/v62/<name>` (snapshot commits, nothing built).
- Eric: v62 does not resume until the kernel crate cuts a release the whole
  refactor can be finished on; persist writes no row fold of its own; from
  here to the tag the work is deletion and de-duplication.
- Eric (relayed by the Constitution session): two critical paths. One:
  Edge / Server / Client / Agent on Agent 2.24. Two: Kernel, Constitution and
  Verify completing what persist needs. They meet at Edge's adoption of v62.
- Read-only audit of the build line (four readers, no code written): only
  four decisions reach the crate today; about 850 to 1,000 functions and 43
  to 48 thousand non-test lines still decide rules over rows in persist
  (BELIEVED size, READ sites). See `DELETE_LIST.md`.
- Kernel audited that list against its integration branch. See the boundary
  in `PLAN.md`.
- Eric (relayed verbatim): "Yes, proceed, and get everything onto a release
  branch, notes included. I would rather they delete the superseded code
  wholesale and do A/B testing etc... but whatever makes the most sense
  strategically, our tests and benchmarks are our strength". This approves
  the read-only mapping against the kernel's work-in-progress branch and
  this branch with its notes. It was not read as permission to write
  refactor code before the kernel tag.
- Branch `release/v62` created from `rescue/v62/wint`; notes added.
- Mapping of persist's rule groups to the crate's public functions started
  (read-only, against `release-0.5.0-wip` at 11804e1). See `KERNEL_MAP.md`.

### Answers recorded today (from the Constitution session; "ruled" = Eric or the text)

- Ruled: every earlier-form door goes with its fold. Nothing from the v61
  row forms is ported.
- Ruled: open self-admission is not a protocol in 1.0. A public community is
  invitation-only; its content and roster are readable by anyone.
- Text: a removed member keeps the key grants it holds and reads what was
  wrapped for it before removal. A `withdraws` on a key grant concludes
  nothing.
- Text: a second pending invitation concludes nothing; it is not refused at
  the door.
- Text: the node keeps the instant it first held a row that opens a window
  and hands it to the crate.
- Reading: a check of one row against the clock stays a door check. No
  verdict over rows is computed from a stated instant or the host clock
  outside the crate's dated queries. The halt latch and its fuse run on the
  node's own clock.
- Reading: an invitee not yet seated is served the invitation row and what
  is public anyway.
- Reading: a key grant is served by its content's placement. A member's
  second node needs a grant naming its own key.
- Reading: persist stores no verdict. It stores the row an undecided answer
  names and asks again when that row lands.
- Kernel: for 0.5.0 persist prunes nothing on its own judgement. Every row
  is kept. A finality answer over seat, content and window rows is not in
  this tag.
- Window lengths and thresholds are law data:
  `constitution/governance_policy.tsv` and `governance_policy_acts.tsv`,
  pinned by the policy pin. Persist loads them and hands them to the crate
  unchanged.
- Vectors: Kernel emits about 60 cases covering each function persist will
  call; Verify's tooling mints them as signed wire statements; persist
  replays them through its own door on both backends.
- Stored shape (READ): `ceg_statements.bytes` is the statement as received;
  the other columns are lookups parsed from it, plus two node-local
  instants (`admitted_us`, `first_held_us`).

### Owed

- By the Constitution repo before the tag: refusal-token delta against
  rc22; member table for new and changed shapes; placement for all 189
  families (JSON and a flat TSV); claim-id delta; retired families, verbs
  and words.
- By Kernel: the wire map (statement to row view), the vector set, yes or
  no on four composition questions (see `PLAN.md`).
- By persist to the Constitution repo: the `mesh_config` payload members
  and signer cell.
- By persist to the Client: the refusal for a retired objection state is
  `namespace_vocab_value_unregistered`.

### Later on 2026-11-27

- `KERNEL_MAP.md` added: persist's rule groups against the crate at
  `release-0.5.0-wip` 11804e1 (READ in source; nothing compiled). Not on
  that commit yet: the audience module, the key-to-person fold, the
  affiliation countersign, a public founder predicate, the wire map and the
  vector schema. Fifteen open points for Kernel are in its section E; sent.
- The `mesh_config` payload members, signer rule and registered keys were
  sent to the Constitution session (READ from `mesh_config.rs`).
- Adapter breaks to expect at the pin, from signatures: `SeatRow::word`
  required; `Policy::SelfAdmit` gone; `SeatLaw` gains `acts`,
  `removal_floor`, `kinds`; `WindowSpec` gains `opener`.
- Kernel's answers to the four confirmations (relayed):
  - Replication audience: being built for 0.5.0 as `seat::person_keys` (a
    person's live keys) and `standing::nodes_of` (the nodes an owner's
    binding covers); with `audience::audiences` they give the node set at a
    row. Persist's own derivation is deleted.
  - Consent peer set: not in the crate (placement only, no acts row, no
    fold). Ships shut unless Edge's sync depends on a consented peer; Edge
    is being asked.
  - Steward purge: needs only an acts-table row and an arm; may be IN
    0.5.0. To be confirmed when the row lands.
  - An invitation is served to the key it names: yes.
- Kernel will ship a function that builds `WindowSpec` from the
  Constitution's policy row unchanged; the same is asked for `SeatLaw`.
  Persist authors no table.
- New Constitution pin candidate: `rc23-next` d5d42bf;
  `manifests/family_model.json` sha256
  94a6ac96a22338752716bce35caa44e50e471479fc01bae5f1a553076a31499f; all
  189 families placed. The policy pin moves once more.
- `mesh_config`: the registered keys become a data file in the
  Constitution repo that persist loads. With the fold shut the door still
  admits and keeps a well-formed row; it concludes nothing. Only a
  malformed row is refused.
- Scope settled for the not-in-this-tag list (relayed): the two musts are
  the minor rule and the consent peer set (Edge's replication to peers a
  person does not own depends on it), both 0.5.1 at latest. Steward purge
  is likely in 0.5.0. `admission:unit` ships shut: Edge does not use it and
  the agent fails closed for units beyond its attested build; when it
  returns it keeps its function name and row shape. Everything else on the
  shut list ships shut. `PLAN.md` updated.
- So the kernel release v62 can finish on is the one that carries the minor
  rule and the consent peer set: 0.5.1 if they do not make 0.5.0.

### Kernel's answers to the map's open points (direct, 2026-11-27; nothing tagged)

- Waiting on a row: being built for 0.5.0. `seat_rule_why` and
  `window::rule_why` return the row waited on; the stalled recovery names
  its bundle; `Held::lacks(id)` gives the missing ids.
- Seats over the Held layer: NOT in 0.5.0. Each roster answer builds its
  graph over the rows handed in (Kernel's figures: about 16 ms to build
  seats and 22 ms for members at a head, at 16 thousand rows). Persist must
  bound the rows it presents per answer and measure this in the A/B
  benchmarks.
- Persons: `seat::Persons`, `persons_of`, `person_at`; every count is over
  persons; the crate maps keys to persons. `seat::person_keys` and
  `standing::nodes_of` complete the node set for a row.
- Root grants: the seat a root grant gives is a root-confirmed offer over
  the room naming the grant; seats read the root view through the cut spec.
- Tables: `window::spec_from_policy(policy row)` and
  `law_from_tables(acts rows, policy rows)`. Persist loads the
  Constitution's files unchanged.
- Nothing is made up except the node's first-held instant. The
  caller-filled fields on `head::Entry`, a stated census figure and a
  roster resolved by the caller are not to be used on a verdict path.
- A version row is not a count's head.
- The election close is in (`seat::election_closed`), under an independent
  re-read.
- Quarantine, slash, takedown, reconsideration, officers and the
  countersign are merging. `is_founder` is public; a live-or-stalled answer
  for infrastructure is being added. Audience and placement are on their
  own lane (189 placed).
- The consent peer set is now IN 0.5.0.
- "Adopting 0.5.0 from 0.2.2" is being written with the wire map and the
  vector schema.
- Further signature breaks to expect: `Conf::Root`; the lone-act seat
  kinds; `AudienceRow::seats` replaced; content kinds `Ack` and `KeyEnd`;
  `CutSpec::key_view`.
- Remaining must not yet in 0.5.0: the minor rule and age band.
- Kernel on the rows to present and on keeping answers:
  - The row set for an answer about an object is NOT only the judged row's
    causal past. It is every held row over that object (concurrent rows
    change answers), the signers' person and key rows (self-roster rows,
    key records, rotations, revocations, owner bindings), the reader's own
    acknowledgement rows, and, where the answer walks them, the root's
    bundles and grants, the trust edges and the authority's record. The
    wire map will state the rows to present per function.
  - Keeping an answer in memory is inside the rule as a pure-function
    cache: keyed on the exact set of row ids presented, the reader and its
    line, the key view's inputs and the table pins. It is dropped on any
    new row that would be in that presented set, never written to the
    store as truth, and never answered from once the set has grown.
  - Design consequence for persist: the presentation needs one "rows for
    object X" selector per function, shared by the door and the cache's
    invalidation, so the two cannot disagree. The fold scheduler's read
    index (`ceg_fold_reads`) is the natural place for it.
- Kernel corrected its answer on the election: the ranked seating and its
  close did not pass the independent read and are NOT in this tag. Plain
  moderator seats, duty conferral, the lone-act and lift paths are
  unaffected. For persist: the election door ships shut unless Eric holds
  v62 for a kernel release that carries it. This conflicts with the
  earlier scope decision that the election stays in v62, so it is his
  call.
