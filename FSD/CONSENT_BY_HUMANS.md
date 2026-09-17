# Consent by humans — stewardship, the triple, and the principal walk (CIRISPersist#857)

**Status:** v44.6.0 design. Filed from CIRISServer#599 ("consent is by humans,
not infrastructure"). Two asks. The first is answered by the constitution's
own structure and needs one producer change plus one substrate fix; the
second is substrate work.

An earlier draft of this document framed the agent relation as ownership and
proposed an owner-binding door targeting agents. It was withdrawn before it
was built. The constitution is explicit and this document follows it.

## 1. Vocabulary, and why it is not style

CC 3.2, the structural no-slavery guarantee: *"Steward-binding is
responsibility, not property: a steward is responsible **for** a ward, never
a holder **of** one. … You never steward a node, an agent, or a person as a
possession; you are responsible for a node, an agent, or a child — and an
adult answers only for themselves."* An agent is *"partnership and agency
under stewardship; the agent retains its constitutional autonomy and
dignity (CC 1.13.2)."*

So the substrate's words are:

| target | relation | the human is the… | single-valued? |
|---|---|---|---|
| node | owner-binding (`delegates_to`, `owner_binding`, `infra:*` only) | **owner** — the responsible party for a device; persist's internal purpose string is literally `responsible_for` | yes (CC 3.2) |
| agent | stewardship — the agent is an **occurrence of the human's identity**, delegated agency, in a **bilateral** partnership the agent accepts | **steward** | the occurrence anchor: one; a custody marker: at most one more (Clause D cardinality) |
| minor | guardianship | guardian | yes |
| adult | un-stewardable | — | — |

"Owner" is reserved for the device relation. Persist never says a human
owns an agent, and no door or fold is named as if one did.

## 2. The triple, and the two edges that are all there is (CC 3.4.7.3)

Clause E states the seam as *"one human in three roles across three keys"*:

```
owner_of(node) == steward_of(agent) == signer_of(envelope)
```

| key | `identity_type` | minted by |
|---|---|---|
| user | `user` | the person's client, hardware-rooted; registered at the first-run root claim |
| node | `node` | Server's `node_signer` as `<alias>-node`; a node refuses to run on an actor key and mints its own (Clause A: substrate or actor, never both) |
| agent | `agent` | the agent's engine bootstrap (`ciris-agent-bootstrap-*`), an Ed25519 seed plus an ML-DSA-65 seed |

**Clause C — the actor↔node relation is entailed, never asserted.** There
MUST NOT be a direct `agent → node` or `node → agent` edge. The human has
standing and exercises it **twice**:

1. **human → node**: `delegates_to(user → node, delegation_purpose:
   owner_binding, infra:*)`. Single-valued; user-signed so a node cannot
   make itself owned (CC 1.13.2); any `agency:*` scope is refused outright.
   Server's root claim (`POST /v1/setup/root`) verifies and persists it.
2. **human → agent**: stewardship. On the wire this is the §8.1.12.7 login
   ceremony, `Engine::self_at_login`: the agent is co-admitted as an
   **occurrence of the human's identity**, delegated agency
   (`delegates_to(user → agent, [act_on_behalf, message_io,
   network_presence, sub_delegation])`), and partnered **bilaterally** —
   the human emits `consent:partnership_grant`, the agent emits
   `consent:partnership_accept`. The agent consents. A node never does.

**Clause D** derives the third relation from the two:
`may_act_through(agent, node) ≔ ∃h. h = owner_of(node) ∧ h ∈ stewards_of(agent)`,
and `stewards_of` is the custody set — *"self-anchor, the `identity_occurrence`
half, and live `delegates_to` granters"*, where for a key that can accept for
itself the delegation half counts **only** with the custody marker. *"An
unmarked `delegates_to(U → agent)` confers a job, not custody."* The
cardinality text names the base case: *"The multi-parent premise is carried by
the occurrence half plus one custody claim."* The occurrence half is the
anchor a login produces; the custody marker is a second, stronger claim.

## 3. Ask 1 — the split home, correctly read

On the desktop/Android install the agent key's only occurrence row names
itself: `identity = agent, occurrence = agent`. That row is **not a defect
and not the missing link**: it is Server `compose`'s boot-published
transport self-occurrence, signed by the engine's own key for edge's
occurrence-KEX reader (CIRISServer#454), and on a split home the engine's key
is the agent's. It is a legitimate row for a different reader.

What is missing is the **occurrence anchor**: no row says the agent is an
occurrence of the human. So clause (2) of `steward_bindings_of` yields no
human, and the scorer falls back to a legacy machine-authored grant. The fix
is not a new binding and not a new fold:

- **Producer (Edge/Server, at install):** the signer that signs the node's
  owner-binding runs the login ceremony for the agent —
  `self_at_login(identity_signer: Some(human), agent: …)`. Since v44.5.0
  (#856) that ceremony publishes the agent occurrence through the gated door,
  identity-signed, so it replicates and a far node's cascade can wrap to it.
  No `owner_of(agent)`; the consumer asks `steward_bindings_of(agent)`, or
  the consent doors below, which ask it for them.
- **Substrate (this cut):** clause (2) is spelled three times
  (`is_steward_bound`, `steward_bindings_of`, `steward_binding_chain`) and
  each resolves the occurrence half through `lookup_identity_for_occurrence`
  — `WHERE occurrence_key_id = ? LIMIT 1` with no order on sqlite and
  postgres, `.values().find(..)` on memory. One occurrence key may be bound
  under several identities (the table's key is `(identity, occurrence)`),
  and on a split home it now is: the transport self-row beside the human's.
  Which row wins is arbitrary, so the human anchors the agent on some backends
  and not others, in some runs and not others. **One helper,
  `user_identity_anchors_of(k)`**, reads every row for the occurrence key
  (`list_identity_occurrences_by_occurrence_key`, v44.4.0), keeps the
  identities that are `user`-role, and keeps only those under which `k` is
  **active** (`list_identity_occurrences_active`) — the v38.2.0 rule that a
  revoked device is not co-self with its former identity. All three clause-(2)
  sites call it. One predicate, three callers (#811's lesson, again).

The custody-marked `delegates_to(user → agent, owner_binding)` stays
admissible — CC 2.4.1.2 names it and Clause D counts it — as the second
anchor. Nothing here promotes it, and no door is added for it.

## 4. Ask 2 — the consent doors take any key and walk to the humans, on rows that name the machine

**The operator's constraint (2026-09-17, via CIRISServer#599):** *"the consent
to ship traces needs to be tied to THIS agent — the consent should not be for
every agent that we are partnered with / responsible for."* A person
responsible for three agents who consented, in one agent's wizard, to that
agent shipping its traces has not consented for the other two. So the walk is
not "any human behind the machine"; it is "any human behind the machine, on a
row that names the machine".

**The member is `for_key_id`.**
- On a `consent:replication:v1` grant it is a payload member of the closed
  grammar: `ConsentTransferPolicy.for_key_id: Option<key_id>`. The grammar is
  `deny_unknown_fields` on purpose, so this is a grammar change and
  **`CONSENT_GRAMMAR_HASH` re-pins**; Edge and Server re-pin exactly as for
  the sixteenth kind in v44.3.0. Putting the member outside the payload would
  be the un-gated member the closed grammar exists to refuse.
- On a `consent:state:*` row it is an envelope member, `for_key_id`, beside
  `scope` and `content_class`; that envelope is not hash-pinned.
- A machine-authored row (attesting = the machine) is about its author by
  construction; `for_key_id` on it is refused if it names another key.

**The doors**, two trait defaults inherited by every backend from one body,
beside the strict projections (which stay, unchanged, for projection-exact
reads):

```rust
/// {k} ∪ steward_bindings_of(k), sorted, deduped.
async fn consent_principals_of(&self, k) -> Vec<String>;
/// k's own peers ∪ peers of each steward's grants whose for_key_id == k.
async fn consent_peers_by_principals(&self, k) -> Vec<String>;
/// k's own stance, and each steward's stance over its rows naming k, combined.
async fn resolve_scoped_consent_by_principals(&self, target, k, scope, qualifier, now) -> ConsentState;
```

For subject `k`: `k`'s own rows fold as today. For each steward `p ≠ k`, only
`p`'s rows carrying `for_key_id == k` enter the fold; a steward's row naming
another agent, or none, is `Unspecified` for `k`. There is no blanket form —
a grant meant for several agents is several grants. A human key is the
identity case (`consent_principals_of(human) = {human}`), so Server's two
call sites keyed by the node and by the owner return one answer.

**The projection carries it.** V147 adds `consent_peer_set_for`
(`author_key_id, for_key_id, peer_key_id, source_attestation_id,
asserted_at`, keyed on the first three), maintained in the same transaction
as V109's `consent_peer_set` and deleted by the same revocation fold, so the
widened read stays a projection read rather than a re-derived fold (#502).
V109 is untouched: its key `(node, peer)` would collide for a human granting
two agents to one peer, and the strict door keeps its exact semantics.

**The combine rule, `combine_principal_stances`, spelled once:** any
`Revoked` → `Revoked`; else any `Granted` → `Granted`; else any `Expired` →
`Expired`; else `Unspecified`. A reverse quorum on the stop under the
accord-ops invariant: any one human standing behind a machine can withdraw
its consent for it, and no human's grant overrides another's revocation,
newer or not. Silence is not refusal; expiry is lapse, not withdrawal.
**An empty steward set is no human, and no human is no consent for the
human's data.** The agent's own consent, within its agency, is untouched.

## 5. Invariants

| # | invariant | falsified by | gate |
|---|---|---|---|
| I94 | An agent bound as an occurrence of a `user` identity (the login shape) has that human in `steward_bindings_of`, `is_steward_bound` and `steward_binding_chain` — **while the agent's transport self-row exists beside it** — on memory, sqlite, postgres. A plain conferral does not steward it. A revoked (inactive) occurrence row stops anchoring. | `LIMIT 1` choosing the self-row; a job read as custody; a revoked device still co-self | behavioural, three backends |
| I94 (b) | The three clause-(2) sites call `user_identity_anchors_of`; none resolves the occurrence half through `lookup_identity_for_occurrence`. | the three spellings drifting again | from disk |
| I95 | Keyed by the machine: the steward's row **naming it** governs; a steward's row naming ANOTHER agent is `Unspecified`; a steward's row naming none is `Unspecified`; keyed by the human, the human's own stance regardless of `for_key_id`; a machine with no principal and no own row is `Unspecified`; a legacy machine-authored grant still counts; two principals (the agent's own row and its steward's row naming it): steward grant + agent silent → `Granted`; agent grant + steward revoke → `Revoked`; the same steward re-granting newer than its own revoke → `Granted`. | one wizard's opt-in covering every agent the person stewards; a grant overriding another principal's withdrawal | behavioural, three backends |
| I96 | `consent_peers_by_principals(agent)` = agent's own peers ∪ peers of the steward's grants with `for_key_id == agent`; a steward's grant for a sibling agent contributes nothing; the split-key defect (strict(node) empty, owner's grant names the node) is non-empty through this door. | zero traces from every split-key home; one grant lighting up three agents | behavioural, three backends |
| I96 (b) | A grant whose `for_key_id` names a key other than its author is refused at admission when the author is a machine; a human author may name any key. `CONSENT_GRAMMAR_HASH` is re-pinned and the pin test names the new value. | infrastructure consenting on another machine's behalf; a silent grammar change | behavioural + pin |
| I97 | Two nodes: `self_at_login` with the human's signer on A admits the agent as an occurrence of the human through the gated door; the row crosses to B; `consent_principals_of(agent)` on B is `{agent, human}`. | an anchor that exists only where it was signed | behavioural, two nodes |
| I98 | `combine_principal_stances` is one function; the scoped door calls it; the trait defaults delegate to the module; the PyO3 mirrors delegate to the Engine. | the rule drifting between doors | from disk |
