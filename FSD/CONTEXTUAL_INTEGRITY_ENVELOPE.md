# The contextual-integrity envelope — fields, axes, and the consent lifecycle

**Status:** v44.7.0 design record + the v44.8.0 cut list. Filed from
CIRISPersist#866 (sub-scoping is two grammars) and #867 (three principles
have no enforcing layer), both from CIRISEdge's transmission-principle
audit. Operator decision 2026-09-18: **the envelope member is normative** —
the scope of a consent is the `scope` member of the `consent:state:granted`
row's own signed envelope, not a companion `consent:scope:{kind}` row.
Constitution erratum: CIRISConstitution#103.

Every claim below marked with a `file::fn` is verified against v44.7.0
source. Claims marked **(cut)** are the work this document commits persist
to, with the invariant that will witness it.

## 1. The frame: five parameters, nine axes

Contextual integrity (Nissenbaum) describes a consented flow with five
parameters — sender, subject, recipient, information type, transmission
principle. CC 4.5.1.1 splits *recipient* into three questions and adds
lifecycle and content, giving the nine axes persist carries as
`namespace::supersets::CI_AXES` and answers explicitly at the federation
crossing (`crossing::ContextualIntegrity`, every axis required, every axis
cross-checked against the row, every mismatch a typed refusal naming the
axis):

| axis | the question | answered by |
|---|---|---|
| `sender` | who is speaking | `attesting_key_id` — the fabric is never the sender of an actor's claim (v39.0.0) |
| `data_subject` | who it is about | `subject_key_ids` (`Nobody` is an explicit answer) |
| `recipient_see` | who may learn it exists | `cohort_scope` + the cohort target (`family_key_id` / `community_key_id`) |
| `recipient_revoke` | who may withdraw it | derived: the producer, plus every `subject_key_ids` member (CC 2.4.1.1) |
| `recipient_receive` | how the bytes reach them | `delivery_mode` (absent ⇔ best-effort) |
| `information_type` | what kind of claim | `dimension` → `attestation_family` |
| `transmission_principle` | under what norm it flows | the consent planes of §3 |
| `temporal_lifecycle` | when it was said, when it lapses, when it must be gone | `asserted_at`, `expires_at`, `deletion_window` |
| `content` | which bytes | the hex SHA-256 of `JCS(envelope)` |

Two of the nine are *consent's own*: `transmission_principle` is where the
consent planes live, and `recipient_revoke` is the authority that ends them.
The other seven are the context a consent is *about*.

## 2. The fields

The signed envelope of an attestation row. "Binds" = who fixes the value
into the signed bytes; "reads" = the production processor that keys a
decision on it. A field with no reader is carried, and this document says
so rather than implying otherwise.

### 2.1 Context fields (on every row)

| member | axis | binds | reads |
|---|---|---|---|
| `attesting_key_id` | sender | the actor, at sign-at-write (`types::LocalAttestationInput::bind_for_signing`) | every emitter-class rule; the consent fold's authorship filter (`consent::fold_stance`: only rows whose `attesting_key_id == subject` enter the universe) |
| `attested_key_id` | the *target* of the claim | the actor | the fold's row selection (`resolve_scoped_consent(target, …)` lists `list_attestations_for(target)`); for a consent row, the target is the party being consented *to* |
| `subject_key_ids` | data_subject; recipient_revoke | the actor | the crossing cross-check; CC 2.4.1.1 withdrawal authority; on a `consent:replication:v1` grant, the **peers** the grant extends to (`consent_peer_set` projection) |
| `dimension` | information_type | the actor | `attestation_family`; the reserved-prefix admission table; the consent folds key on the `consent:state:` prefix (`consent::consent_dimension::STATE_PREFIX`) |
| `cohort_scope` (+ `family_key_id` / `community_key_id`) | recipient_see | the actor; a widening is a NEW `supersedes` row, never an edit (v39.0.0) | `crossing::check_widening`; the put door's membership proof (AV-45); `Audience::discoverable` (CC 5.2: `self` / `family` never emit `holds_bytes`) |
| `delivery_mode` | recipient_receive | the actor | the delivery plane |
| `asserted_at` | temporal_lifecycle (created) | the actor; bound at write and cross-checked at admission (`admission::check_instant_binding`, #598 — the typed column must equal the signed member) | every fold's clock component; the SLA watch's revocation instant |
| `expires_at` | temporal_lifecycle (lapse) | the actor | the fold drops a lapsed row from the candidate set (`fold_stance`: `expires_at > now`) |
| `deletion_window` | temporal_lifecycle (erasure) | the producer | the deletion-window watch (`deletion_window::run_deletion_window_watch`, §5.8) |
| `additional_scrubs[].cosigned_at` | temporal_lifecycle (modified) | the co-scrubbing node, OUTSIDE the preimage | `MeshCrossing::age_at_crossing` (CC 2.6.7) |

### 2.2 Consent fields

| member | on which rows | binds | reads |
|---|---|---|---|
| `scope` (string or array of tokens) | `consent:state:*` | the subject (or a `delegates_to` chain rooted at one; a human under #857) | `consent::matches_scoped_query` — **the normative carrier of the transmission-principle scope** (§3.1, §4) |
| `content_class` | `consent:state:*` | the subject | `matches_scoped_query`'s qualifier: CC 3.3.12's content-classification vocabulary, used by the Server infohazard gate (`view` + `medical`, CIRISServer#161/#243). Orthogonal to `scope`; both may apply |
| `for_key_id` | `consent:state:*` (envelope) and `consent:replication:v1` (payload) | a HUMAN author naming the machine the consent is for | `consent_by_humans::for_key_id_of`; `admission::check_consent_for_key_admission` (a machine may name only itself, #857); the V147 `consent_peer_set_for` projection |
| `consent_supersedes` | `consent:state:{revoked\|expired}` | the subject | `consent::causal_edge` / `causal_rank` (#642): a revocation that NAMES the grant it ends out-ranks the clock; an unresolved edge is evidence of an incomplete view and reads restrictively until the named row arrives |
| `withdrawal_reason` | `withdraws` | the producer | descriptive only |
| `payload` (`ConsentTransferPolicy`) | `consent:replication:v1` | the granting node (or a human naming `for_key_id`) | `consent_grammar::parse_grant_payload` — ONE strict parser, `deny_unknown_fields`, a malformed grant rejects whole; `Engine::promote_consented_backlog`; `admission` at put (`validate_grant_admission`) |

The transfer policy's members, and who reads each (`engine::promote_consented_backlog`):

| member | closed vocabulary | read by the promoter |
|---|---|---|
| `grants` | required token | parse |
| `direction` | `egress` (default) / `ingress` | yes — only `egress` is actioned |
| `kinds` | `EnvelopeKind::ALL` (default `["Attestation"]`) | yes |
| `attestation_prefixes` | dimension prefixes | yes — the covered set |
| `audience` | `cohort_scope` (default `federation`) | yes |
| `valid_until` | instant | yes — a lapsed grant covers nothing |
| `restrictions` | `strip_field` / `recipient_capability` | `strip_field` yes — the placement's strip set (`engine.rs` `load_active_egress_grants` → placement); `recipient_capability` is parsed and **not actioned** on the send path |
| `for_key_id` | key id | not by the promoter — read by the #857 admission gate and the V147 `consent_peer_set_for` projection, which the by-principals send-set doors consult |
| `principle` | `retain` / `share` (default) / `analyze` / `train` / `publish` | **no — carried only.** A `principle: train` grant replicates exactly like `share` today. **(cut C2)** |
| `purpose` | free text | descriptive |

## 3. The three consent planes and how they relate

Persist carries the transmission principle on three planes. They share a
vocabulary and nothing else; conflating them is how "`share` decides the
send set" got into a downstream document.

### 3.1 The stance plane — `consent:state:*`

A **subject's** standing stance toward a **target**, scoped. Rows:
`consent:state:granted`, `consent:state:revoked` (subject-emitted),
`consent:state:expired` (substrate-emitted per CC 3.3.1 — see §5.7). The
scope is the envelope `scope` member (§4). Resolved by
`FederationDirectory::resolve_consent_state` (all scopes) and
`resolve_scoped_consent(target, subject, scope, qualifier, now)`, both one
body (`consent::fold_stance`, v36.0.0), and by the `*_by_principals` doors
that walk from any key to the humans it stands for (#857).

Who asks:

| consumer | scope | when |
|---|---|---|
| **persist** `admission::check_capacity_consent_admission` | `analyze` | at admission of a federation-tier `capacity:*` row whose attester ≠ subject (CC 3.4.5 / CIRISConstitution#46) — refused before persistence unless `Granted` |
| CIRISServer infohazard gate | `view` + `content_class` | before serving classified content (CIRISServer#161/#243) |
| the crossing | — | `CrossingBasis::ConsentGrant` is verified against a live **transfer** grant (§3.2), not a stance |
| the processor (Agent CEM / LensCore) | `train`, `publish` | **nobody today** — carried-only until adopted (§6) |
| persist retention | `retain:<duration>` | **not yet** — the sweeps act on `Revoked` state (cut C1) |

### 3.2 The transfer plane — `consent:replication:v1`

A **node's** (or, via `for_key_id`, a human's) standing, auditable consent to
replicate a named dimension-prefix set to named **peers**
(`subject_key_ids`) at an **audience**. This is the send set: the V109
`consent_peer_set` and V147 `consent_peer_set_for` projections are
maintained in the same write as the grant and folded by the same revocation;
`promote_consented_backlog` ships the covered backlog. Hash-pinned
(`CONSENT_GRAMMAR_HASH`); a member added to the closed grammar moves the
hash and every consumer re-pins. `share` on the stance plane is **not** this
plane: a stance says what the subject permits, the transfer grant says
where the node sends.

### 3.3 The crossing plane — `enter_mesh` / `widen_audience`

The moment a row's answers become irrevocable because edge replicates it on
its next round (v39.0.0). `transmission_principle` here is
`CrossingBasis`: `ProducerAuthority` (the actor's own claim, the admission
stack decides whether that suffices — consent-gated families refuse it
there) or `ConsentGrant { attestation_id }` — a live, self-authored, egress
transfer grant covering this dimension at this audience, verified against the
stored grant (`crossing::check_contextual_integrity`).

### 3.4 What is NOT a plane

A `consent:scope:{kind}` **dimension row**. CC 3.3.1's row and its
composition pattern describe the scope as companion attestations; no fold in
persist (or Server, or the CEM) selects one. Persist admits such a row as an
ordinary `consent:` reserved-but-not-prefix-gated dimension
(`admission::RESERVED_BUT_NOT_GATED_BY_PREFIX_RULE`) and it confers nothing.
Run the CC's pattern literally — a bare granted row plus companions — and
`resolve_scoped_consent(.., "analyze")` is `Unspecified`, so the `capacity:*`
gate refuses. That is fail-closed and it is also the constitution's common
case being inert; hence the erratum (CIRISConstitution#103), not a second
fold.

## 4. The scope token grammar **(cut C1)**

### 4.1 Syntax

```
scope-member := token | [ token, … ]
token        := kind ( ":" sub )*
kind         := "retain" | "share" | "analyze" | "train" | "publish"     -- transmission_principle::ALL
sub          := [a-z0-9_-]+                                             -- per-kind meaning, §4.2
```

- `kind` is closed — `types::transmission_principle::ALL`, the same five the
  transfer grammar pins. A token whose kind is not one of the five is not a
  consent scope; today it silently matches nothing (a grant naming an
  unrelated scope is "unrelated"). After C1 it is **refused at admission**
  for `consent:state:*` rows, the v44.4.0 canonical-id posture: never admit a
  token the fold cannot match.
- Sub-scopes ride IN the token (CC 3.3.1: `retain:90d`,
  `share:cohort:family`). `content_class` stays a separate member.
- `CONSENT_GRAMMAR_HASH` does not move: the `scope` member is not in the
  pinned manifest (`FSD/CONSENT_BY_HUMANS.md`). The `envelope_vocabulary`
  hash does not move either — no new member name.

### 4.2 Per-kind sub-scope semantics

| kind | sub form | meaning | kind of constraint | honoured by |
|---|---|---|---|---|
| `retain` | `retain:<n>d` / `retain:<n>h` (a duration) | keep the bytes for at most this long from `asserted_at` of the grant | lifecycle **bound** | persist retention sweep (C1b); the deletion-window watch reads the tighter of this and the row's `deletion_window` |
| `share` | `share:cohort:<cohort_scope>` | propagate no wider than this audience | audience **narrowing** | the crossing (`Audience` ⊆ the narrowing) and any caller asking `share` at an audience |
| `analyze` | `analyze:<family-prefix>` | derive scores only in this family | information-type **narrowing** | `check_capacity_consent_admission` asks `analyze:capacity` (a bare `analyze` grant still covers it) |
| `train` | open | reserved for the processor | narrowing | processor (§6) |
| `publish` | open | reserved for the processor | narrowing | processor (§6) |

### 4.3 Matching

`matches_scoped_query(row, query, qualifier)` becomes, for a row token `g`
and a query token `q`:

1. `kind(g) == kind(q)`, else unrelated (unchanged: a row naming other
   scopes never reads as blanket).
2. For a **narrowing** kind: `g` covers `q` iff `sub(g)` is absent (a bare
   grant is the widest) or `sub(g) ⊇ sub(q)` in that kind's order
   (`cohort_scope` widening order for `share`; prefix containment for
   `analyze`). A narrowed grant does **not** cover a wider ask: a caller must
   ask at the audience it intends, and a bare `share` query means
   `federation`.
3. For a **bound** kind (`retain`): `g` covers `q` iff kinds match; the
   duration is not a match criterion, it is a lifecycle fact the resolver
   returns alongside the stance (`ScopedStance { state, retain_until }`,
   C1b) and the retention sweep enforces.
4. Then the `content_class` qualifier, exactly as today.
5. The asymmetry is unchanged (v16.1.1): a **non-grant** naming no genuine
   scope is BLANKET and matches every query; a **grant** naming no genuine
   scope matches nothing; latest-wins by `(causal_rank, asserted_at)`.

### 4.4 Refusal at the door

Both the local write door and ingest admission for `consent:state:*` rows
parse every token. Refused, by name: unknown kind; a sub-scope on a kind
whose sub form is closed (`retain`, `share`, `analyze`) that does not parse
(`retain:soon`, `share:cohort:everyone`); a `share:cohort:<x>` wider than the
row's own `cohort_scope` (a grant cannot permit propagation the row itself
does not reach). Open kinds (`train`, `publish`) accept any well-formed sub.

## 5. The lifecycle

### 5.1 Create

The **subject** — or a `delegates_to` chain rooted at the subject, or a
**human** who stewards the machine (#857, `for_key_id` names which machine)
— emits a `consent:state:granted` row targeting the party consented to
(`attested_key_id`), naming its scope(s) in the envelope. Signed at write:
`LocalAttestationInput::bind_for_signing` binds `asserted_at` into the
preimage and the actor's hybrid signature becomes the base scrub; a deferred
local row therefore has something to co-scrub later. A node emits a
`consent:replication:v1` grant with the closed payload for the transfer
plane. Producers: the CIRISAgent CEM (stances), Server `compose` / the login
ceremony (the human's stances with `for_key_id`), Edge (transfer grants as
the operator's replication policy).

### 5.2 Admit

The stack a consent row runs at `put_attestation`, in order
(`admission.rs`, the `check_*` sequence at the local/ingest doors):

1. row–column binding (`check_row_column_binding`): every typed column equals
   its signed member;
2. cohort standing and target (`check_cohort_standing_resolved`,
   `envelope_cohort_target`): a family/community placement is a membership
   the door proves;
3. instant binding (`check_instant_binding`, #598): `asserted_at` typed ==
   signed, within skew;
4. peer de-admission (`check_peer_deadmission`);
5. reserved-prefix admission (`check_reserved_prefix_admission`) — `consent:`
   is reserved and **not** prefix-gated; the per-leaf emitter class of CC
   3.4.5 is enforced by the fold's authorship filter (§5.5), not here;
6. **the analyze gate** (`check_capacity_consent_admission`) — on the
   `capacity:*` row being scored, not on the consent row;
7. then, in each backend's put door (all three, parity-gated):
   `for_key_id` (`check_consent_for_key_admission`, #857 — a machine author
   may name only itself) and the transfer-grant grammar
   (`consent_grammar::validate_grant_admission` — whole-grant reject on any
   non-conforming member);
8. **(C1)** scope-token parse for `consent:state:*` rows (§4.4), beside 7.

### 5.3 Cross

`enter_mesh` (byte-identical, the actor's base scrub, the node may co-scrub)
or `widen_audience` (a new `supersedes` row, strictly wider). The caller
states all nine axes; `check_contextual_integrity` cross-checks each against
the row; `transmission_principle` is producer authority or a named live
transfer grant. A row authored at `(local, self)` crosses to
`(federation, self)`: replicated to the owner's own nodes by consent fan-out,
not discoverable (CC 5.2).

### 5.4 Replicate

The transfer plane decides the send set. `Engine::promote_consented_backlog`
loads the live egress grants (`load_active_egress_grants`: `direction ==
egress`, `valid_until` / `expires_at` not passed, `kinds`,
`attestation_prefixes`), computes a placement per covered row (the audience
the covering grants agree on, the `strip_field` set from their
`restrictions`), and runs `enter_mesh` / `widen_audience` for it. Who
receives is the V109 / V147 projection of the grants' `subject_key_ids`
(`consent_peers` / `consent_peers_by_principals`, the latter filtered to
live stewards). `principle` is not consulted **(C2)**: after the cut, only
`share` (and `publish`, for the external plane) authorize propagation;
`retain` / `analyze` / `train` grants cover nothing on the send set, and the
promoter's report names the principle it declined. `recipient_capability`
restrictions are parsed and not actioned — noted here, filed as part of C2.

### 5.5 Resolve

`fold_stance(rows, subject, now, scoped)`:

1. universe = rows for the target whose `attesting_key_id == subject` and
   whose dimension starts `consent:state:` — the emitter class, enforced
   where it matters;
2. candidates = universe minus lapsed (`expires_at`), filtered by
   `matches_scoped_query` when scoped;
3. winner = max by `causal_fold_ordering_key` =
   `(causal_rank, asserted_at, restriction_rank, attestation_id)` — a
   revocation naming its grant (`consent_supersedes`) beats the clock; an
   unresolved edge reads as an incomplete view and stays restrictive; among
   clock-tied rows the more restrictive stance wins (`restriction_rank`:
   `Granted` ranks lowest, `Unspecified` above it — an unrecognised stance
   never resolves as consent);
4. stance = the winner's `consent:state:*` leaf, else `Unspecified`.

`*_by_principals(target, k, …)`: the anchors of `k` (`k` itself, plus the
active human identities `k` is an occurrence of), each resolved, combined by
`combine_principal_stances` — any `Revoked` → `Revoked`; else any `Granted`;
else any `Expired`; else `Unspecified` — a human's revocation is a brake, and
rows that name a *different* machine in `for_key_id` are not this machine's.

### 5.6 Honor — who enforces each principle

| principle | enforcing layer | mechanism | status |
|---|---|---|---|
| `analyze` | **persist** | `check_capacity_consent_admission` at admission | enforced (v22.0.0) |
| `share` (stance) | the crossing / callers | a stance is what the subject permits; the **transfer grant** is what the node sends | stance carried; propagation governed by §3.2 |
| `retain` | **persist** | retention sweeps + the SLA watch honour `retain:<duration>` | **(C1b)** — today the sweeps act on `Revoked` only |
| `train` | the processor (Agent CEM / LensCore) | `resolve_scoped_consent_by_principals(target, k, "train", …)` before training | **carried-only** until adopted; the door exists |
| `publish` | the processor | same door before any external publication | **carried-only** |
| `principle` (transfer) | **persist** | the promoter | **(C2)** — carried-only today |

A subject that declines `analyze` cannot be scored: `capacity:composite` is
undefined for them (CC 3.4.5 — consent gates scoring, never accountability;
the role-gated abuse-response families are untouched).

### 5.7 Change and expire

A later `granted` naming the scope re-opens it (latest-wins among rank-0
rows). A `revoked` naming no scope is blanket. A `revoked` carrying
`consent_supersedes = <grant id>` ends that grant regardless of clock skew.
Widening is a new row; the prior row is never edited.

`expires_at` on a grant lapses it at fold time. CC 3.3.1 says
`consent:state:expired` is **substrate-emitted** when `valid_until` passes
without renewal; persist recognises the leaf in the fold
(`consent::consent_state_of`) but **emits no such row today** — expiry is
computed, not recorded. **(C3)**: a sweep emits `consent:state:expired` with
`consent_supersedes` naming the lapsed grant, signed by `substrate_persist`,
so the lapse is a replicable fact with a causal edge rather than a
per-node clock reading.

### 5.8 Delete

Two commitments, two watches, one posture — evidence, never a verdict:

- **`consent:deletion_sla:{days}`** (a producer row at publication). On a
  subject's revocation, `FederationDirectory::run_consent_sla_watch(now,
  promotion_window)` walks `list_consent_revocations`, finds the target's
  latest SLA row, computes `revoked_at + days`, and — unless the producer has
  emitted `consent:deletion_complete` — records `hard_case:consent_sla_breach`.
- **`deletion_window`** (a signed member of the row itself, the erasure
  deadline, #519 c1). `deletion_window::run_deletion_window_watch(now)`
  sweeps stored rows: a window that has passed with the row still present and
  no deletion proof is a breach, recorded through the same `hard_case:*`
  surface (v22.0.0: "the network itself raises a breach signal").

Neither watch erases. Persist deletes what *persist* holds through its
retention plane; a producer's own stores are the producer's duty, and the
breach is how a subject learns it was not done. A persist-side flag is never
sole evidence for `slashing:*` — the WA quorum is.

### 5.9 Decay

`consent:decay:{stage}` (`identity_severed` / `patterns_anonymized` /
`complete`) is substrate-emitted per CC 3.3.1. Persist has no decay
protocol and emits no such row; the CIRISAgent 90-day decay is the agent's.
**(C4)**: mark the leaf as agent-emitted in the CC row or give persist the
sweep — a decision for the Agent team, filed with them.

## 6. Documentation of duty (the #867 answer)

Persist provides the doors; it enforces `analyze` today and `retain` after
C1b; it will read `principle` on the transfer plane after C2. `train` and
`publish` are the processor's, through the existing door, and are
**carried-only** until a processor adopts them — no reader, and no subject,
should believe a `train` revocation is honoured before then. This table is
the contract; a processor that adopts a token files against this document.

## 7. Invariants (witnessed by the v44.8.0 cut)

- **I104** — a `consent:state:*` row whose `scope` carries an unknown kind,
  or a closed-kind sub-scope that does not parse, is refused at both doors
  by name; the row is not stored.
- **I105** — `share:cohort:family` covers a query `share:cohort:family` and
  `share:cohort:self`, does not cover `share` (federation) or
  `share:cohort:community`; a bare `share` covers all of them.
- **I106** — `retain:90d` resolves `Granted` for `retain` with
  `retain_until = asserted_at + 90d`; the retention sweep evicts the covered
  bytes after that instant and not before; a later `retain:180d` extends.
- **I107** — the CC's literal composition pattern (bare granted + companion
  `consent:scope:*` rows) still resolves `Unspecified` — the erratum is the
  fix, not a second fold; pinned so nobody adds one.
- **I108** — a transfer grant with `principle: train` promotes nothing;
  `share` promotes; the promoter's report names the principle it declined.
- **I109** — `consent:state:expired` is emitted by the sweep for a lapsed
  grant, carries `consent_supersedes` naming it, and out-ranks a clock-later
  re-grant that does not name the expiry.
- **I110** — from disk: `matches_scoped_query` is the only scope matcher;
  every door that reads a scope token calls it; the five kinds appear in
  exactly one place.

## 8. The cut list

| id | what | where | hash |
|---|---|---|---|
| C1 | scope-token parser, per-kind match, refusal at both doors | `consent.rs`, `admission.rs`, the local door | none |
| C1b | `retain:<duration>` honoured by retention + the SLA watch; `ScopedStance` return | `retention/`, `consent.rs`, trait + PyO3 | none (new return type on a new door; the old door stays) |
| C2 | `principle` read by the promoter; `recipient_capability` actioned or refused at parse | `engine.rs`, `consent_grammar.rs` | none |
| C3 | `consent:state:expired` emission sweep | new sweep, `substrate_persist` signer | none |
| C4 | decay emission — decide with the Agent team | — | — |
| — | CC erratum | CIRISConstitution#103 | — |

## 9. Not in scope

- A fold over `consent:scope:*` dimension rows (I107 forbids it).
- Moving `content_class` into the token: it is CC 3.3.12's content
  classification, an orthogonal axis the Server gate depends on.
- Any change to `CONSENT_GRAMMAR_HASH`: the stance `scope` member is not in
  the manifest; if a later cut adds the sub-scope production to the manifest
  it re-pins deliberately, like v44.3.0 and v44.6.0.
- Deleting a producer's stores: the SLA watch reports; persist erases only
  what persist holds.
