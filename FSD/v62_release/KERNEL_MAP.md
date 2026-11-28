# KERNEL_MAP: persist's rule groups onto `ciris_kernel` 0.5.0-wip

Read-only map, 2026-11-27. Crate: `CIRISKernel` branch `release-0.5.0-wip` at `11804e1` ("Merge root-fold (03f334b)"),
crate dir `crates/ciris-kernel` (paths below are relative to it unless prefixed). Persist: `CIRISPersist-wint/src`
(pin `kernel-v0.2.2`, `Cargo.toml:700`). FOUND = the item was read in the crate source. NOT FOUND = no public item
was found. `WIRE_MAP.md` and `VECTORS.md` do not exist anywhere in the kernel repository.

Modules present (`src/lib.rs:38-55`): conferral, content, cut, derived, graph, head, held, held_view, key_end, layers,
line, ops, ranked, root, seat (+ `seat/election.rs`), standing, trust, window.
**Absent on this branch:** an `audience` module (place / audiences / carried), a key-to-person fold, an affiliation
countersign, a public `is_founder`, a wired cross-object chain (see B9, B12, B13 and E).

---

## A. The presentation

### A.1 Traits and value types persist implements or fills

| Trait / type (crate file:line) | Method / field | What persist supplies (per crate docs) |
|---|---|---|
| `Row` (`src/lib.rs:59`) | `type Id`, `type Key` | `RowId` (`persist_row_hash`), key id (ADOPTING.md:14) |
| | `id()` `:69`, `names()` `:71`, `signer()` `:73` | own digest; every digest the signed bytes name (`references_attestation_id`, `prev_head_digest`, `charter_digest`); `attesting_key_id` (ADOPTING.md:14, :21-22) |
| `Dated: Row` (`src/lib.rs:76`) | `type Instant`, `asserted_at()` `:80`, `valid_until()` `:83` | signed `asserted_at`; `expires_at` / `valid_until` (HELD.md:340-341). Needed for every `_at` answer |
| `seat::SeatRow: Row` (`src/seat.rs:146`) | `type Word` | scope / policy word (`String` today) |
| | `seat_kind()` `:150` | Offer, Accept, Withdraw, Unseat, Cosign, Ballot, Decline, Ack, Other (`SeatKind`, `:121`) |
| | `word(s)` `:156` **required (new)** | the caller's word for a crate-named scope (`moderate`) |
| | `to` `:158`, `scope` `:164`, `obj` `:168`, `conf` `:172`, `under` `:176` | keys named; scope (on a withdrawal: the one seat it ends); object as `Obj::Row`/`Obj::Key` read by `Obj::from_reference` (`:99`); who confers; the offer it is under |
| | `cosigners` `:180`, `subjects` `:184`, `sub` `:188`, `head` `:192` | verified cosignatures only (ADOPTING.md:57); subjects; sub-delegation flag; the heads it is counted over |
| | `consensus_protocol` `:201` **MUST implement** | the founding record's / record change's protocol word (`:199-200`: default `None` means no room has a protocol) |
| | `cohort_subkind` `:206`, `group_kind` `:212`, `protocol_entrenched` `:218`, `admission_quorum_basis` `:223`, `dissolves` `:228` | record fields: `infrastructure`; `family`; entrenched flag; `founders`; `dissolved_at` present |
| | `bundle` `:234`, `role` `:240`, `regime` `:245`, `lifts` `:253` | recovery widening's grant row; `founder` role on admission / founders' amendment; protocol+policy in force at the act; lift flag on an end |
| | `policy` `:257`, `counted` `:261`, `over` `:265`, `need` `:271` | the policy row word; the counted body (must be the act's own body, ADOPTING.md:159-162); `over` (not read for a count, H2); declared threshold (never read under a protocol) |
| | `of` `:276`, `target` `:280`, `content` `:284` | accepted offer / receipted act / election; withdrawn row; cited row (lift cites the removal) |
| | `duties` `:288`, `duty_holders` `:299`, `weights` `:305` | record's declared duties; founding `duty_holders` map; record weights (each key once) |
| | `options` `:309` (not read for the election), `ranking` `:313`, `signing_key` `:320`, `room` `:324`, `private_room` `:331` | ballot ranking best-first; the key the door verified; acknowledged room; `membership: private` from the founding row only |
| `cut::CutSpec<R>` (`src/cut.rs:20`) | `type Slot`, `type Say`, `key_slot` `:26`, `on_slots` `:28`, `cuts_of` `:30`, `says` `:32` | slots a row is on / cuts (seat slot `(seat, key, scope, object)`, ADOPTING.md:16) and what a cut says |
| | `need` `:34`, `rejects` `:38`, `is_voice_for` `:42` | distinct signers a cut needs; ids it voids (rule 3); whether a cosign is its voice |
| | `trust_root()` `:48` | a `RootView` (normally `root::RootReading`) for a stalled recovery; `None` = undecided |
| `seat::SeatLaw` (`src/seat.rs:472`, `Default`) | `duties`, `holds`, `confers`, `ends`, `final_scopes`, `roster_seats`, `depth`, `policy` | the duty law and the policy table as values (ADOPTING.md:24-26); `final_scopes` = `registered`, `member`, `agent` (ADOPTING.md:425-426) |
| | `acts: Option<Vec<ActRule>>` `:498` (new) | `governance_policy_acts.tsv` rows; `None` = no binding |
| | `removal_floor` `:502` (new), `kinds` `:506` (new) | `community_remove` floor cell (2); founding scope -> `CommunityKind` |
| `seat::ActRule` (`src/seat.rs:655`) | `act`, `scope`, `kind`, `policies`, `choice` | one acts-table row (`Act`, `ScopeClass`, `CommunityKind`, `Choice` have `from_word`, `:531`) |
| `window::WindowRow: SeatRow` (`src/window.rs:65`) | `type T`, `win_kind` `:69`, `window` `:71`, `target_key` `:75`, `says` `:79`, `receipt` `:83`, `at` `:87` | Open/Answer/Receipt/Landing; window name; eviction target; the word said; the landing's receipt; one signer's own instant (ADOPTING.md:17) |
| `window::WindowSpec<T>` (`src/window.rs:150`) + `Clause` `:137`, `How` `:94`, `Base` `:114` | `counted`, `concluder`, `opener`, `opener_says`, `at_once`, `silent`, `at_close`, `default`, `target_votes`, `secs` | built from `governance_policy.json` family rows by the caller; looked up through `window::Tables` (`:191`) by the opener's `window()` name |
| `key_end::KeyEndRow: Row` (`src/key_end.rs:31`) | `type T`, `record()` `:35` -> `Record` `:51` (`key, from, until, succ_of, at_old, sigs, end`), `statement()` `:39`, `revocation()` `:43` | `KeyRecord` fields; `identity_type` mapped to `EndRule` by the caller (ADOPTING.md:18) |
| `head::Entry<I,K,T>` (`src/head.rs:86`; `Entry::new` `:136`, `with_at` `:162`) | `id, names, kind, signer, head, of, members, q, sigs, length, receipt, duty, delete, stub, concl, final_counts, settled_stub, ackers, acks, dropped, at` | the header a rule reads (ADOPTING.md:19); `receipt` = the instant this node first held a window opener (node-local); `members`/`q` of a roster version |
| `line::LineSpec<R>` (`src/line.rs:22`) | `counted_act`, `ack_by`, `acknowledges` | crate ships `seat::SeatLine` (`src/seat.rs:1383`); persist needs none of its own for seats |
| `held::HeldSpec<R>` (`src/held.rs:37`) | `well_formed`, `conclude`, `seeded`, `root`, `keys`, `can_carry` | the door's shape check and the conclusion rule (e.g. `window::rule` else `seat::seat_rule`); keys a row carries for wake-ups |
| `held_view::Encode` (`src/held_view.rs:71`) | `encode`, `decode` | provided for `[u8; N]`, ints, `String`; needed for `checkpoint`/`resume` |
| `root::RootBundle` (`src/root.rs:46`) | `id, family, version, prev, holders, seats, charter, duties, sub_delegation, names, recovery, settles, recovers, iat, statements` | each `ceg-genesis-bundle/2`, statements' signatures checked by the store |
| `root::RootGrant: Row` (`src/root.rs:97`) | `is_grant, attached_head, cosigns, halts, bundles, to, scope, signers, duty` | root grants, acceptance edges (attached_head_digest), grant cosignatures, holder halts |
| `root::Revocation` (`:130`), `root::Reader` (`:140`: `anchor, thumbs, acks, after`), `RootReading` (`:1395`: `root, reader, identity`) | | revocations with bound; this node as reader (acks in causal order; `after` per device row); each key's identity type (`Identity { user, node }`, `:1385`) |
| `conferral::ConferralRow` (`src/conferral.rs:81`) | `id, kind, signer, head, of, target, via, sub_delegation, lifts` | rows of one standing (`Kind` `:37`) |
| `conferral::Past<I>` (`:119`) | `in_past(a,b) -> Result<bool, I>` | the store's past; `Err(id)` = the row to fetch |
| `conferral::Standing` (`:131`) | `role, other_standing, who, reader_acks, deputy_depth` | roles, reader's acknowledged heads, cap (`DEPUTY_DEPTH` = 5) |
| `standing::StandingRow` (`src/standing.rs:68`) | `id, kind, signer, head, on, owner, target, lifts, via, sub_delegation` | bundle versions, bindings, acceptances, acts, grant end, receipts, removals |
| `content::ContentRow` (`src/content.rs:94`) + `content::Seat` (`:130`) | `id, kind, signer, head, prev, tips, retracts, extends, seat` | room rows; the caller marks each roster version `SeatAt` for the member (ADOPTING.md:411-414) |
| `seat::GroupCount` (`src/seat.rs:4894`) | `policy, offer, to, members, voices, need` | a resolved count (contract `:4873-4917`) |
| `trust::Accepts` (`src/trust.rs:16`) | `src, dst, classes, depth` | live acceptance edges |

### A.2 What the docs forbid or require of the caller

| Rule | Where |
|---|---|
| A row reaches the kernel verified; `cosigners()` lists verified signatures only | ADOPTING.md:56-57 |
| `signing_key` is the key whose signature the door verified, never a client-supplied value or a value the row states | ADOPTING.md:186-187; `src/seat.rs:316-321` |
| `via` must be derived from the signed row, never from the caller's own reckoning | ADOPTING.md:492-493 |
| Give the real past (an act's names) | ADOPTING.md:509-511 |
| A row of no object (a synthesised version row), a note, an acceptance, a withdrawal or a cosignature naming itself is no head; a count naming one concludes nothing | ADOPTING.md:262-263; `src/seat.rs:4298-4304` (H8). Contradicted by CHANGELOG.md:380-384 (see E1) |
| A counted row's `head` is exactly the newest counted changes over its own object in its own past | ADOPTING.md:258-262; CHANGELOG.md:561-600 (H1, H4) |
| Do not offer again a member who carries over; drops are Unseats | ADOPTING.md:256-257 |
| Do not present the founding as chained counted rows; present one founding Offer, `Conf::Own` | ADOPTING.md:322-326 |
| A later node given as `Conf::Own` seats nobody, with no error | ADOPTING.md:254-255 |
| State `counted()` as the act's own body or not at all | ADOPTING.md:159-162 |
| Present a resignation / removal as one row; do not also unseat each duty | ADOPTING.md:366-369 |
| Present the widening before or with a conferral on a key | ADOPTING.md:362-365 |
| Must not present an agent's duty seat unless the owner's statement was checked at the door | ADOPTING.md:71-73, :384-386 |
| Refuse at the door any infrastructure protocol word other than `quorum:{M}/{N}`; refuse `lifts_on_own_end` rows | ADOPTING.md:105-106, :410 |
| `private_room` from the founding row only | ADOPTING.md:429-430; `src/seat.rs:327-330` |
| Keep `SeatLaw::final_scopes` as the table gives it | ADOPTING.md:424-426 |
| Collapsing several keys of one person is the caller's (until a voice's key roster is built) | ADOPTING.md:205-206, :447-449 |
| No instant comparisons across signers; an `_at` answer takes its instant from a held row, never a clock | ADOPTING.md:211-212; `src/lib.rs:72-75`; `src/window.rs:5-6` |
| `now` forms are node-local readings for serving and display, not for a verdict | `src/key_end.rs:196-198`; `src/head.rs:762-765`; HELD.md:274-278 |
| A `HeldSpec` impl must not capture a clock (not enforceable; "the caller's lint") | HELD.md:277-278 |
| Call the crate over the rows an answer reads, not the whole store (quadratic) | ADOPTING.md:61-63; README.md:237-239 |
| `act_of`: "a caller must not rely on a ranked seating" | `src/seat.rs:705-706` (see E11) |
| Not checked by the crate, caller's door: a delegation term (`stands_at` reads only the seating offer's own instants), a proposal's `expires_at`, that an act's signer is the node a binding binds, the room key being a live `key` seat of the voice | ADOPTING.md:457-458, :74-75, :512, :418-419 |
| A store should not treat a founders' act over an infrastructure room as final on one line | ADOPTING.md:294-297 |
| Permitted caller-made inputs (stated, not forbidden): a synthetic signer on a founding row if not in `to` (ADOPTING.md:252-253); `Base::Stated(n)` census figure, unchecked (ADOPTING.md:526-528); a caller-resolved roster into `group_count` (`src/seat.rs:4918-4919`); `head::Entry` header fields `members`/`q` (`src/head.rs:100-104`) | |

---

## B. Rule groups -> crate items

Signatures shortened: `p` = `&layers::Past`, `c` = `&layers::Concluded`, `law` = `&SeatLaw`, `spec` = `&impl CutSpec`.
"Undecided" column says how the crate expresses "waits on a row" and which row it names.

### B1. Roster replay / standing / last founder / forked roster / dissolution
Persist: `federation/mod.rs` `fold_roster`, `sort_roster_events`, `prepare_roster_events`, `roster_event_verdict`, `authorized_*_roster_at`, `verify_membership_quorum`; `roster_head.rs`; `family_dissolution.rs`.

| Status | Crate item | Pass | Returns / undecided |
|---|---|---|---|
| FOUND | `seat::conclude(kept_rows, law, spec, other, root) -> Concluded` (`src/seat.rs:4037`) | kept rows (`layers::kept`, `src/layers.rs:17`), law, cut spec, rule for non-seat rows | per-row bool; a row naming an unheld id waits (`Graph::waiting`, `src/graph.rs:537`), never concluded |
| FOUND | `seat::seat_rule(p, law, spec, other) -> bool` (`:4021`) | one row's concluded past | bool; undecided recovery is `false` (no typed undecided) |
| FOUND | `seat::for_reader(c, law, spec, own: Option<&Key>) -> (Concluded, BTreeSet<Id>)` (`:3517`) | concluded rows, reader key | rows as they conclude for that reader + changes void for it |
| FOUND | `Seats::new(c, law, spec, own)` (`:1757`), `Seats::for_reader(c, law, spec, own, void)` (`:1764`) | output of `for_reader` | snapshot; `holders(s,o,root)` `:2293`, `stands(k,s,o,root)` `:2259`, `roster(o)` `:2285`, `one(s,o)` `:2302` |
| FOUND | `Seats::holders_at(s,o,root,at) -> Option<Set>` (`:2602`), `stands_at` (`:2620`) | `R: Dated`; `at` = a held row id | `None` when `at` not held / states no instant |
| FOUND | `seat::members_at(p, law, spec, obj, heads, scope)` (`:3139`), `members_in` (`:3652`), `members_in_scopes` (`:3666`), `left_in_past` (`:3697`), `stay_ended_in_past` (`:3743`) | a counted row's past and its named heads | key set; empty when a head is not held (`members_in_scopes` `:3676`) |
| FOUND (forked) | `Seats::tips(o)` (`:2308`), `tips_common(s,o)` (`:2338`), `tips_fold(s,o)` (`:2388`) | | `None` with one tip; tips differing in `regime()` do not fold |
| FOUND (dissolution) | `SeatRow::dissolves()` (`:228`), `Seats::dissolved(o) -> bool` (`:2267`), `Act::Dissolve` (`:578`) | the counted record version carrying `dissolved_at` | bool |
| NOT FOUND | last-founder rule | | ADOPTING.md:153: "No last-founder rule is the kernel's" |
| NOT FOUND | a public "roster at a host instant" (persist's `authorized_*_roster_at(now)`) | | by design: read at the named head or `holders_at(.., at)` |

### B2. Counts
Persist: `federation/consensus.rs` `evaluate`, `eligible_seats`, `quorum_need`, `required_signatures`, `explain_refusal`; `admission.rs` quorum-at-head 5027-7300; `kernel/consensus.rs`, `kernel/law.rs` `ARMS`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `seat::count_members(p, law, spec) -> Set` (`:4150`), `seat::voices(r, p) -> Set` (`:3763`) | counted row's past | the base and voices the seat rule uses |
| FOUND | `seat::met(policy, yes, n, declared) -> bool` (`:3878`), `met_wide` (`:3885`) | counts | bool |
| FOUND | `seat::group_count(&GroupCount, weight) -> Option<bool>` (`:4920`) | resolved roster | `None` only for `Policy::Ranked` |
| FOUND | `seat::Policy` (`:338`: AtLeast, Strict, StrictFloor, Recall, One, Declared, Protocol, Ranked, DutyConfer, DutyWithdraw, Unanimous, Weighted, Lift, NotACount) | law.policy map | |
| FOUND (protocol -> policy) | `seat::act_of(law, get, row) -> Option<(Act, ScopeClass, CommunityKind)>` (`:714`), `seat::policy_for(law, act, scope, kind) -> Option<(&[String], Choice)>` (`:1311`), `seat::kind_of(law, get, obj)` (`:671`) | law with `acts: Some` | policy rows an act may take |
| FOUND | `seat::protocol_record(p, obj) -> Option<&R>` (`:856`), `protocol_of(p, obj)` (`:880`), `RoomProtocol::parse` (`:418`), `parse_in(w, infra)` (`:440`), `community_protocol(w, need, weights)` (`:925`) | | `None` where two concurrent changes disagree (no protocol in force; removals wait) |
| FOUND (supersede quorum) | record change = `Act::RecordChange` under `cosigned_act&default_standing` (acts table; CHANGELOG.md:985-990) | | |
| FOUND (weighted) | `Policy::Weighted` with the record's `weights()`/`need()` (`:367-370`) | | |
| FOUND (ranked) | `ranked::ranked(ballots, options, floor, declared) -> (Option<O>, usize)` (`src/ranked.rs:13`), `ranked::runoff` (`:100`) | | `None` on a tie for weakest |
| NOT FOUND | persist's `quorum_need` high-water latch / a counted row's own `need` under a protocol | | a quorum's `m` is the word's, never the row's (`src/seat.rs:268-273`, `:384-385`) |
| NOT FOUND | `custom:` / `reverse_quorum` policy cells | | persist test `kernel/law.rs:142-145` already asserts none |

### B3. Founders and the trust-root community
Persist: `canonical_community.rs` (`founders`, `check_founder_eligible`, `accord_quorum_over_community`, `infrastructure_constraint`), `trust_root_group.rs` (`holder_founder_counts_at`), admission.rs founder_only / infrastructure 19361-20280.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `seat::kind_of(..) == CommunityKind::Infrastructure` (`:671`, `:691`) | founding row with `cohort_subkind` | |
| FOUND | `seat::founders_of(get, obj) -> usize` (`:887`) | founding row | count of founding signers in `to` only |
| FOUND | `Seats::holders("founder", o, None)` (`:2293`) | | founders at the snapshot |
| FOUND (stall) | `seat::stalled_recovery(p, law, spec) -> Option<&'static str>` (`:1134`) | recovery-shaped row (`bundle()` set) | `Some("stalled_recovery_needs_bundle")` = undecided, names no row |
| FOUND | `seat::recovery_verdict(p, law, spec) -> Result<(), &str>` (`:1163`) | `CutSpec::trust_root()` returning `RootReading` | `Err("stalled_recovery_needs_bundle")` with no root read |
| FOUND (accord) | `CommunityKind::Accord` (`:631`), body `holder` (`:902`), acts `halt_confirm`/`resume`/`standing_act` (acts table) | | |
| NOT FOUND | public liveness / stall predicate (M+1 active founders) | | `founders_at` is private (`src/seat.rs:4194`) |
| NOT FOUND | public `is_founder` | | absent |
| NOT FOUND | accord "m-of-n OR reverse quorum" path | | no reverse-quorum policy |

### B4. Invitation and acceptance
Persist: `membership_acceptance.rs` (`is_standing_proposal`, `answered_proposal_of`, `as_proposal`), `self_roster.rs` `is_roster_key_at`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | seat as two consents inside `seat::seat_rule` (`:4021`); `SeatKind::Accept` with `of()` the offer (`:125`, `:276`) | the joiner's own Accept row | an admission seats where the acceptance is in the counted row's past (ADOPTING.md:304-307) |
| FOUND | `policy_for(law, Act::Admit, ScopeClass::Member, CommunityKind::Community)` -> `cosigned_act|community_invite` (`:1311`; acts table) | | |
| FOUND | decline of an offer = withdrawal (ADOPTING.md:437-438) | | |
| NOT FOUND | proposal expiry (`expires_at`) | | door check, ADOPTING.md:74-75 |

### B5. Objections (reverse quorum, windows)
Persist: `reverse_quorum.rs` (`fold_reverse_quorum`, `resolve_reverse_quorum`, `dismissal_required`).

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `Policy::Lift` (`:376`), `seat::lift_voices(p, law, spec) -> Option<(Key, Set)>` (`:3819`) | the lift row citing the removal; objections it names | removal's author and the voices |
| FOUND | `window::rule` / `outcome` with `Base::Others`, `How::MoreOfVoted` (`src/window.rs:94`, `:114`) | | see B18 |
| NOT FOUND | a reverse-quorum count / dismissal / escalation as a crate rule | | none in src (grep `reverse_quorum`: 0) |

### B6. Two-path / lone act after a silent window / cosign holds
Persist: `two_path.rs` `decide`, `decide_all`; `cosign.rs` count parts; `second_signer_voice.rs`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `window::rule(p, windows, law, spec) -> Option<bool>` (`src/window.rs:479`) | `Tables` closure -> `WindowSpec` | `None` = not a window row |
| FOUND | `window::outcome(c, pid, windows, law, spec, cut_counts) -> Outcome` (`:576`) | concluded rows, opener index | `Outcome::{None, Open, Contested, Landed(String)}` (`:176`); `Open` = waiting on answers/landing, names no row |
| FOUND | `WindowSpec.silent`, `default`, `at_once`, `at_close` (`:150-173`) | | lone act = default outcome via a landing row |
| FOUND | `window::author_apart` (`:409`), `ballot_words` (`:415`), `own_withdrawals` (`:433`), `unwithdrawn` (`:448`) | | |
| FOUND (cosign) | `SeatKind::Cosign`; `seat::voices` counts a cosignature naming every head (`:3763`) | | |
| NOT FOUND | a cosign "hold" lapse as a sweep | | ADOPTING.md:38: a lapse is a window answer read at `now` |

### B7. Persons, node-bearing seats, self-roster heads
Persist: `key_person.rs` (`seat_person`, `voice`, `of_devices`), `NodeBearingSeats`, `self_roster.rs`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `seat::persons(m, agents) -> Set` (`:1420`), `AGENT` (`:1414`), `NODE` (`:1417`) | | removes agent/node keys only |
| FOUND | self roster: `Obj::Key`, `CommunityKind::SelfRoster` (`:629`), acts `admit/remove key self` (acts table) | | |
| NOT FOUND | key-to-person fold (several device keys = one voice) | | caller's: ADOPTING.md:205-206, :447-449 (persist's `PersonsAt::voice`, `seat_person`) |
| NOT FOUND | node-bearing intervals | | "persist data", HELD.md:318-322; `covers_at` (`src/lib.rs:89`) offered for per-interval reads |

### B8. Heads / tips / merge / contested founding
Persist: `edition2/head_rule.rs`, `group.rs` (lineage, merge, `forked_tip_members`), `genesis.rs` tips, `group_supersede_admit.rs::held_head_verdict`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `Seats::tips` / `tips_common` / `tips_fold` (`src/seat.rs:2308`, `:2338`, `:2388`) | | |
| FOUND | `line::settle` (`src/line.rs:137`), `void` (`:199`), `own_line` (`:51`), `counted_acts` (`:44`), `versions(ids, builds_on, past, valid, ack)` (`:244`) | | |
| FOUND | `graph::Graph::frontier` (`src/graph.rs:654`), `concurrent` (`:646`), `in_past` (`:602`) | | |
| FOUND | `head::View::tips()` (`src/head.rs:803`) | | |
| NOT FOUND | "contested founding" of a room as a rule | | a founding row is its own object (`Obj::Row(own id)`); for bundles see `Root::contested` (B9) |

### B9. Trust root
Persist: `trust_root.rs` (charter tally, capability walk, transit eligibility), `trust_root_group.rs`, `edition2/genesis.rs` (`bundles_in_force`, `genesis_in_force`), `halt.rs`, `recovery_signer.rs`, `peer_rooting.rs`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `root::Root::new(bundles, revs, grants)` (`src/root.rs:195`) | `RootBundle`s, `Revocation`s, lane rows | |
| FOUND | `Root::counted(id) -> Result<(), Reason>` (`:457`), `void()` (`:616`), `void_reason` (`:608`), `contested(ids)` (`:1027`), `fold(tips)` (`:1119`), `bounded_settler(b)` (`:550`) | | `Reason` strings |
| FOUND (holders in force) | `Root::in_force(rd) -> Option<(holders, seats)>` (`:1111`), `heads(rd)` (`:923`), `first(rd)` (`:811`), `reader_line(rd)` (`:833`), `no_say(rd)` (`:995`) | `Reader` | `None` = not anchored (`genesis_bundle_not_anchored`) |
| FOUND (root grant) | `Root::grant_in_force(gid, rd) -> Result<(), Reason>` (`:1329`), `grant_row` (`:1244`), `seen_of` (`:1273`), `grant_voices` (`:1290`), `grant` (`:1370`) | | |
| FOUND (charter coverage) | `Root::scope_in_force(rd)` (`:1312`), `Root::sub_delegation(gid, rd) -> Option<bool>` (`:1304`) | | |
| FOUND (halt) | `Root::halt_in_force(hid, rd) -> Result<(), Reason>` (`:1360`) | `RootGrant::halts()` row | halt confirmation count: window `accord_halt`; "the halt's own path ... is not built here" (CHANGELOG.md:61-62) |
| FOUND (recovery keys) | `RootBundle::recovery()`, `recovers()` (`:83`, `:90`) inside `counted` | | |
| FOUND (capability walk) | `trust::reaches(edges, from, c, budget, a)` (`src/trust.rs:39`), `honours` (`:123`), `EdgeIndex` (`:83`), `HOP_CAP` = 5 (`:35`); `derived::live_edges`, `reach`, `means` (`src/derived.rs:94`, `:121`, `:145`) | | |
| FOUND (seat view) | `root::RootReading` (`:1395`) implementing `RootView` (`:1443`: `recovery_grant`, `sub_delegation`, `seat_grant`) | | |
| NOT FOUND | transit eligibility | | no item (grep `transit`: 0) |
| NOT FOUND (unwired) | cross-object chain root grant -> room seat / delegation | | `RootView::seat_grant` and `sub_delegation` exist (`:1450-1457`), no caller in `src/seat.rs` |

### B10. Key plane
Persist: `edition2/liveness.rs` (`may_revoke`, rotation chain), `register.rs` key-statement standing, `occurrence.rs`, `key_end` adapter.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `key_end::well_formed(r, ceil) -> bool` (`src/key_end.rs:71`), `conclude_rule(p) -> bool` (`:92`) | | |
| FOUND (key end) | `live(c,k,now)` (`:138`), `ended` (`:147`), `retained(c,now)` (`:156`); `live_at(c,k,at) -> Option<bool>` (`:199`), `ended_at` (`:208`), `retained_at` (`:217`) | `R: KeyEndRow + Dated` | `None` when `at` not held |
| FOUND (rotation, rivals) | `key_end::successor(c, k, ret) -> Option<Key>` (`:226`) | | `None` when two keys are spoken |
| FOUND (suspect statements) | `retained` / `retained_at`: rows of an ended key no live row has in its past lapse | | |
| FOUND (who may revoke) | `KeyEndRow::revocation` = the key's own; an owner's revocation = Unseat of `owner` with `SeatLaw::ends = {owner:[owner]}` (CHANGELOG.md:1595-1606) | | |
| NOT FOUND | community DEK / epoch identity, private-room bindings | | ADOPTING.md:68 |

### B11. Delegation and duties
Persist: admission.rs delegation walk 11134-12740, licensure 7292-7850, owner/steward 13131-16760, moderation/duty 20700-22930.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND (delegation walk) | `Seats::stands` (`src/seat.rs:2259`) with `SeatLaw::confers`, `depth`; onward grants `Conf::Seat` + `under()` (ADOPTING.md:451-458) | | bool |
| FOUND (deputies) | `conferral::answers(rows, standing, past) -> Result<Answers, Refused>` (`src/conferral.rs:472`) | rows of one standing | `Answer::Undecided(id)` names the row to fetch; `Refused::SeveralEnds` |
| FOUND (licensure) | `trust::honours` (`src/trust.rs:123`) | | |
| FOUND (duty holders) | `Seats::holders(duty, o, None)`; `Policy::DutyConfer`/`DutyWithdraw`; one-founder room seats `moderate` via `SeatRow::word` | | |
| FOUND (moderators) | lone removal of an agent key inside `seat_rule`; `Policy::Lift`; receipts `SeatKind::Ack` with `of()` the removal | | |
| FOUND (election) | `seat::is_election(law, r)` (`:3109`), `seat::election_closed(c, law, spec, seating) -> bool` (`src/seat/election.rs:733`), `ELECTION_RANKS` = 3 (`:41`) | | |
| FOUND (recall) | `Policy::Recall(2,3,2)` for `moderator_recall` | | |
| FOUND (owner binding) | `Seats::one("owner", o)` (`:2302`); `standing::answers` (B15) | | |
| NOT FOUND | steward binding as a crate rule | | no `steward` item |
| NOT FOUND | slash / quarantine / takedown acts | | only duty words in `SeatLaw::duties` doc (`:473`) |

### B12. Affiliation
Persist: `affiliation_config.rs` (`deciding_seats`, `check_one_voice_countersign`, `designated_official_keys`).

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `CommunityKind::Affiliation` (`src/seat.rs:633`); acts row `remove member affiliation affiliation_member_action|cosigned_act row` | | |
| NOT FOUND | officer seats (`role: officer`) | | no `ScopeClass`/`Act` |
| NOT FOUND | one-officer countersign | | absent on this branch |

### B13. Audience and wrap set
Persist: `replication_audience.rs`, `key_grant.rs`, `at_rest_cascade.rs`, `chunk_dag_cascade.rs`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `Seats::roster(o)` (`src/seat.rs:2285`): "Content, wraps and audience read it" (`:2282-2284`) | | key set |
| NOT FOUND | `audience` module (place / audiences / carried) | | absent; `head::View::carried` (`src/head.rs:681`) is an act's force at a later head, not an audience |

### B14. Who is served
Persist: `edition2/serve.rs`, `group_serve.rs`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `content::answers(rows, seat, past) -> Answers` (`src/content.rs:336`), `content::changed(rows, arrived, seat, past)` (`:448`) | one member, one room | `Answer::Undecided(id)` |
| FOUND | `Seats::roster(o)` | | |
| NOT FOUND | routing / serving rule (hold, offer, serve, relay, park, discard) | | "not stated" (ADOPTING.md:64-65; README.md:205-207) |

### B15. Ownership
Persist: `kernel/owner.rs`, `ownership_reclaim.rs`, admission.rs `owner_of`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `Seats::one("owner", o)` (`src/seat.rs:2302`), `holders_at` (`:2602`) in place of persist's `expires_at > now` filter (HELD.md:342-343) | | `None` on two live owners |
| FOUND (grant issuer chain) | `standing::answers(rows, grant, past) -> Outcome` (`src/standing.rs:338`) | bundle versions, bindings, acceptances, acts | `Answer::{Stands, Nobody(Nobody), Undecided(id)}`; `Nobody::TwoOwners` |
| NOT FOUND | ownership reclaim petition / WA finding as a rule | | acts row `finding any body wa_adjudication` only |

### B16. Steward purge, settled, receipts
Persist: `steward_purge.rs`, `engine.rs` `purge_finalize`, `edition2/receipts.rs`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `head::purge(store, own, now, reading) -> (Store, Vec<Id>)` (`src/head.rs:816`) | entries | new store + checkpoint tips |
| FOUND | `head::View::new(store, extra, own, reading, say)` (`:311`), `receipts` (`:585`), `counts_at` (`:675`), `carried` (`:681`), `settled` (`:710`), `closed_for_me` (`:724`), `missing` (`:739`), `acked` (`:522`) | | `missing` returns keys whose clean receipt is not held |
| NOT FOUND | steward selection / who may purge | | |

### B17. Quarantine fold, takedown standing
Persist: `quarantine.rs` (`fold_quarantine`, `resolve_quarantine`).

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND (partial) | a takedown holder's standing: `Seats::holders("takedown", o)`; an act under an ended standing: `conferral::answers` | | |
| NOT FOUND | quarantine fold, withhold / release markers | | grep `quarantin`: 0 |

### B18. Windows as rows
Persist: `federation_vote_windows.first_held_at`, `fold.rs` `hold_window_secs`, `lapse_short_counted_rows`.

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `WinKind::{Open, Answer, Receipt, Landing}` (`src/window.rs:50`); `window::rule` (`:479`), `outcome` (`:576`) | receipt = `window:held`, landing = `window:landed` rows (ADOPTING.md:521-522) | `Outcome::Open` while waiting |
| FOUND | `head::View::window_at(o, at) -> Option<WindowState>` (`src/head.rs:751`), `answers_at` (`:757`); `window(o, now)` (`:766`) node-local | | |
| NOT FOUND | binding of a window table to an act | | "stay the caller's: no act binding reads them in this tag" (ADOPTING.md:175-176) |

### Held / HeldView (incremental layer)
Persist: `edition2/fold.rs` scheduler (`hold`, `reads`, `Dep`, refold).

| Status | Crate item | Pass | Returns / gap |
|---|---|---|---|
| FOUND | `held::Held::new(spec, rows)` (`src/held.rs:357`), `empty` (`:278`), `admit(&R) -> Result<Admitted, Refused>` (`:368`), `admit_foreign` (`:378`), `admit_all` (`:464`) | rows borrowed `&'a R` | `Admitted { kept, waiting, dirty, visited, wake, foreign }` (`:178`); `Refused::{Duplicate, NotWellFormed}` (`:169`) |
| FOUND | `Held::register(Reads) -> AnswerId` (`:553`), `update` (`:561`), `unregister` (`:571`), `wakes_for` (`:605`), `unwritable` (`:621`), `reads_of` (`:521`), `recorded_reads` (`:534`), `named_by` (`:511`) | `Reads::of(ids, keys)` (`:84`) | `Admitted::wake` lists answers to re-run |
| FOUND | `Held::waits(id) -> bool` (`:659`), `waiting()` (`:663`), `holds` (`:655`), `concluded_id` (`:667`) | | waiting is a bool; the missing id is not returned |
| FOUND | `held_view::HeldView::new(store, own, reading, say)` (`src/held_view.rs:233`), `admit(Entry)` (`:302`), `view()` (`:265`), `checkpoint() -> Vec<u8>` (`:518`), `resume(bytes, rows) -> Result<Self, CheckpointError>` (`:565`), `conflict_key` (`:148`) | entries owned | `CheckpointError::{Version, NotCanonical, Truncated, Missing(id), Differs(id)}` (`:121`) |
| FOUND | `held::differential` (`src/held.rs:693`), `differential_foreign` (`:701`), `held_view::differential` (`src/held_view.rs:703`) | persist's own row mixes | `Result<(), Mismatch>` |
| NOT FOUND | `Seats` / `members_at` / `window` over a held view (incremental seat count) | | follow-up only (HELD.md:113-115, :192-193) |
| NOT FOUND | a typed "waits on row X" for `seat_rule` / `window::rule` | | only `conferral`, `standing`, `content` return `Undecided(id)` |

---

## C. Persist's current adapter vs the crate

Persist pins `kernel-v0.2.2` (`Cargo.toml:700`). Calls found by grepping `ciris_kernel` in `src/` (only `src/kernel/*.rs` import it; `federation/consensus.rs`, `store/edition_baseline.rs`, `federation/delegation_cycle_invariants.rs` mention it in comments).

| Persist file | Crate items called | On `release-0.5.0-wip` |
|---|---|---|
| `kernel/view.rs` | `Row`; `impl SeatRow for KRow` (`:281`); `impl WindowRow` (`:330`); `impl KeyEndRow` + `Record`, `EndRule` (`:352`); `impl CutSpec for NoCut` (`:374`); `seat::{Conf, Obj, Reference, SeatKind, SHA_256, IDENTITY_PREFIX}` | **breaks**: `SeatRow::word` is required (`src/seat.rs:156`). Compiles otherwise; `consensus_protocol` not implemented -> no room protocol (`src/seat.rs:199-200`); `CutSpec::trust_root` defaulted; no `Dated` impl (needed for any `_at` form) |
| `kernel/law.rs` | `seat::{Policy, SeatLaw}`; `window::{Base, Clause, How, WindowSpec}` | **breaks**: `Policy::SelfAdmit` removed (`law.rs:35`; CHANGELOG.md:11-13); `SeatLaw { .. }` literal without `..Default::default()` lacks `acts`, `removal_floor`, `kinds` (`law.rs:44`; CHANGELOG.md:455-458, :977); `WindowSpec { .. }` literal lacks `opener` (`law.rs:107`; CHANGELOG.md:1579-1580) |
| `kernel/consensus.rs` | `layers::{kept, conclude}`; `seat::{seat_rule, Conf, Obj, SeatKind}`; `seat::group_count`, `GroupCount` | compiles (signatures unchanged: `src/seat.rs:4021`, `:4894`, `:4920`). `ballot_rows` presents a synthesised version row as head: H8 makes such a count conclude nothing (`src/seat.rs:4298-4304`; ADOPTING.md:262-263) |
| `kernel/owner.rs` | `derived::fold_default`; `graph::Graph`; `layers::{self, Concluded}` (`Concluded::with`, `.g`); `seat::{seat_rule, Conf, Obj, SeatKind, Seats}`; `Seats::new`, `Seats::holders` | compiles (`Concluded.g` still pub, `src/layers.rs:57`; `Seats::new` 4 args `:1757`; `holders(s,o,root)` `:2293`; `fold_default` `src/derived.rs:179`). Host-clock pre-filter replaced by `holders_at` (HELD.md:342-343) |
| `kernel/trust.rs` | `derived::fold_default`; `layers`; `seat::Obj`; `trust::{reaches, Accepts}` | compiles (`src/trust.rs:16`, `:39` unchanged); uses `p.row()`, `p.get()` (private-field change of 0.3 does not reach it) |
| `kernel/key_end.rs` | `key_end::{well_formed, conclude_rule, live, ended, EndRule, KeyEndRow, Record}`; `layers`; `Row` | compiles (`src/key_end.rs:71`, `:92`, `:138`, `:147`); caller-passed `at: u64` instant -> `live_at`/`ended_at` read the instant from a held row |
| `kernel/content.rs`, `content_invariants.rs` | `content::{self, answers, changed, Answers, Answer, ContentRow, Kind, Rule, Seat, SeatAt}` | compiles (`src/content.rs:94`, `:336`, `:448` unchanged in shape) |
| `kernel/head.rs` | `head::{Entry, Kind}` (`Entry::new`); `graph::Graph::new`, `frontier`; `Row` | compiles (`Entry::new` sets `at: None`, `src/head.rs:136`) |
| `kernel/differential.rs`, `kernel/mod.rs` | none directly (persist-internal) | |

Breaking changes the CHANGELOG states since 0.2.2:

| Release | Change | CHANGELOG line |
|---|---|---|
| 0.3.0 | `layers::Past` fields private (`Past::new`, `graph()`, `ancestors()`, `index()`) | :1814, :1829-1832 |
| 0.3.0 | `head::Entry` gains `at: Option<T>` | :1815, :1834-1835 |
| 0.3.0 | `held::Admitted` gains `wake` | :1816, :1833 |
| 0.3.0 (from 0.2.2) | `WindowSpec` gains `opener`; `window::How::MoreAtLeast`, `window::Base::Opener` (exhaustive match) | :1579-1581 |
| 0.3.x (slice 4) | `held::Admitted` gains `foreign` | :1772-1774, :1762 |
| 0.4.0 | `standing::Nobody::TwoOwners`; `SeatRow::duty_holders` (defaulted) | :1226-1229, :1293 |
| 0.4.0 | `conferral::Standing` gains `deputy_depth`; `conferral::Rule::{Depth, NoSub}` | :1542-1544 |
| Unreleased | `Policy::SelfAdmit`, `RoomProtocol::SelfAdmit`, `RoomProtocol::states`, `SeatLaw::community_floor` removed | :11-13 |
| Unreleased | `root::Reader::after` (new field) | :63 |
| Unreleased | `seat::for_reader` takes `Option<&Key>` | :139 |
| Unreleased | `SeatKind::Decline` (new variant); `seat::election_closed` new | :147-148 |
| Unreleased | `Policy::StrictFloor`, `Policy::Recall` (exhaustive match); `ranked::runoff` new | :262-263 |
| Unreleased | `SeatRow::word` required | :355, :376-379 |
| Unreleased | `SeatLaw` gains `acts`, `kinds` | :455-458 |
| Unreleased | `standing::Nobody` gains `NotTheGrantee`, `EdgeNotAnAct`, `TooDeep` | :486 |
| Unreleased | `window::Base::Stated` (exhaustive match) | :494-496 |
| Unreleased | `Policy::Protocol` (exhaustive match); `SeatRow::consensus_protocol` | :815-824 |
| Unreleased | `SeatLaw::removal_floor` | :977 |
| Unreleased | `SeatRow::consent_one` gone | ADOPTING.md:171 |

Answer changes since 0.2.2 that reach persist's call sites (no signature change): heads ruling H1-H8 (CHANGELOG.md:561-600); tips fold in `Seats::stands`/`holders` (:1571-1572); `window::outcome` met at-once count with no landing (:1573); on a plain count the removed member is a voice (:1688); re-admitted member counts (:237-259); CC 2.7.7 rule 5 over every counted act (:20-36); one target per counted end (:5-9); key record end outside it (:1102).

---

## D. Data files

The crate embeds no data (no `include_str!`/`include_bytes!` in `src/`). Every table is a value the caller builds.

| File (`data/`, repo root) | Content | Handed to the crate as |
|---|---|---|
| `governance_policy.tsv` / `.json` (pin `a304b485...`, Constitution rc23 `76965eb`; `data/README.md:3-8`) | one row per decision family: enact / cancel / floor, window, length | `SeatLaw::policy: BTreeMap<String, Policy>` (`src/seat.rs:492`) and `window::WindowSpec` per family via `Tables` (`src/window.rs:191`); `SeatLaw::removal_floor` from `community_remove`'s floor cell (`:499-502`). Caller parses (crate tests: `tests/common/mod.rs:733-775`) |
| `governance_policy_acts.tsv` (52 lines) | (act, scope, community kind) -> policy rows, `fixed`/`row` | `SeatLaw::acts: Option<Vec<ActRule>>` (`:498`), words via `Act`/`ScopeClass`/`CommunityKind`/`Choice::from_word` (`:531`); `SeatLaw::kinds` (`:506`). Caller parses (`tests/common/mod.rs:777-800`) |
| `consensus_protocols.tsv` | closed protocol set | built into the crate: `RoomProtocol::parse` / `parse_in` (`src/seat.rs:418`, `:440`), `PROTOCOL_KINDS` (`:404`) |
| `governance_policy_vectors.json` | policy-table vectors | not read by the crate ("here for reading") |
| `transitions.json` | per family acts / scopes / key effects | not read by the crate (`key_plane_model.py`) |
| `witnesses.tsv`, `divergences.*`, `ui_primitives.json` | model inputs, divergence list, screen draft | not read by the crate |
| `crates/ciris-kernel/tests/fixtures/*.json` | conformance fixtures (`conferral_two.json`, `seat.json`, `acts.json`, ...) | test inputs; ADOPTING/README point adopters at `conferral_two.json` cases (README.md:168-172) |

Other caller-supplied values: `key_end::well_formed`'s `ceil` (`src/key_end.rs:71`); `conferral::DEPUTY_DEPTH` (5, `src/conferral.rs:147`); `trust::HOP_CAP` (5, `src/trust.rs:35`); `held::PAST_WINDOW` (64, `src/held.rs:246`).

---

## E. Open points for Kernel

1. A version row of no object as a count's head: CHANGELOG.md:380-384 says it is of the object's line (persist's `ballot_rows`); ADOPTING.md:262-263 and `src/seat.rs:4301` (H8) say it is no head. Which stands for 0.5.0?
2. `seat_rule` and `window::rule` return `bool`/`Option<bool>`: how does a store tell "waits on row X" from "concludes nothing" (e.g. `stalled_recovery_needs_bundle`), as `conferral`/`standing`/`content` do with `Undecided(id)`?
3. `Held::waits(id)` is a bool: will the crate return the unheld id(s) a waiting row names, or is that the store's `names - held`?
4. When do `Seats`, `members_at` and `window::outcome` run over a `Held`/`HeldView` (HELD.md:113-115)? Until then every roster answer rebuilds a graph over its rows.
5. The key-to-person fold (several device keys = one voice) is the caller's (ADOPTING.md:205-206, :447-449): is the absent "key-to-person fold at a row" the replacement, and what row presents it?
6. Is `Seats::roster(o)` the audience and wrap set for 0.5.0, or will the absent `audience` module (place / audiences / carried) be merged first?
7. Founder liveness / stall and "is a founder" are private (`founders_at`, `src/seat.rs:4194`): will `is_founder` and a live/stalled answer be public?
8. `RootView::seat_grant` / `sub_delegation` (`src/root.rs:1450-1457`) have no caller in `seat`: what is the cross-object chain's row shape and entry point?
9. Will the crate ship a parser (or embed the pinned table) for `governance_policy.json` / `governance_policy_acts.tsv` into `SeatLaw` and `WindowSpec`, so a store keeps no mapping table of its own?
10. `act_of` says "a caller must not rely on a ranked seating" (`src/seat.rs:705-706`) while the election is "back in this tag" (CHANGELOG.md:147): is `election_closed` safe to adopt in 0.5.0?
11. Windows are "the caller's: no act binding reads them in this tag" (ADOPTING.md:175-176): which family row gives each window's spec, and will the acts table bind them?
12. `head::Entry` carries caller-filled `members`/`q` and a node-local `receipt` instant: should a store derive them from `Seats` at the head, and is `receipt` permitted in a verdict path?
13. Affiliation officer seats and the one-officer countersign: no `ScopeClass`/`Act` exists; planned for 0.5.0 or later?
14. Slash / quarantine / takedown, steward purge selection, transit eligibility and routing have no crate rule: which of these are in the kernel's scope?
15. Release shape: ADOPTING.md:233 names tag `kernel-v0.4.0`; what tag will 0.5.0 carry, and will the CHANGELOG carry an "Adopting 0.5.0 from 0.2.2" table like :1568?
