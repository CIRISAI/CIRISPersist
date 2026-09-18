# The same-key rebind door for a registration record (CIRISPersist#864)

**Status:** v44.7.0 design. Filed from the CIRISServer/CIRISAgent 0.5.211
adoption (CIRISAgent#1178); Server's half is CIRISServer#606.

## 1. The blocker

Every CIRISVerify v15.2.0 peer refuses a `Key` envelope whose
`registration_envelope` does not bind its subject (#659, v31.0.0:
`verify_envelope_binds_subject` requires `identity_type`, `key_id`, both
pubkeys and `valid_until`, and *"an absent field is a REFUSAL, not a
tolerated legacy shape"*). The canonical's directory holds 1,560 key rows:
1,030 bound; **529 `agent` keys with an empty envelope**; and **one `user`
key (2026-07-02) whose envelope is `{"key_id": …}`**, stewarding nine client
nodes. That user's record rides the first identity round to every new peer,
is refused, and the identity round never completes — no trace round, every
receipt `held 0`. Upgrading the canonical to v44.6.0 changed the gates and
not the stored rows.

The holder cannot repair it: `put_public_key` refuses an existing `key_id`
with different content (`Conflict`), which is right against replacement and
wrong against the key's own holder re-signing a bound envelope for the same
pubkeys; and no rotate / re-register door exists for a key record.

## 2. What a registration record is, and what "rebind" means

A `federation_keys` row is the holder's claim *"this key_id is these two
pubkeys, of this identity_type"*, carried as `registration_envelope` +
`original_content_hash` + a hybrid scrub signature by `scrub_key_id`. When
`scrub_key_id == key_id` the record is **self-signed**: proof of possession
of the very pubkeys the row carries. When an accord anchor scrubs it, the
record is **anchor-scrubbed** and its authority comes from the anchor.

A pre-#659 row is not a wrong identity. Its pubkeys are the holder's and
every attestation the key signed verifies against them. What is wrong is the
**envelope**: it binds nothing, so a peer cannot tell whether the holder
claimed *this* identity_type and *these* pubkeys. A **rebind** replaces only
that claim, with one the same holder signs over the same pubkeys — nothing
that identifies the key or confers authority may move.

There is already a monotonic, verify-before-mutation plane for key records:
`plan_replicated_key_apply` classifies an incoming record against the stored
row into `Insert / Upgrade / Supersede / Unchanged / Refused{reason}`, and
the backends run the corresponding atomic store step. The rebind is one
more arm of that plan, so the local door and the receive side admit it by
the same rule.

## 3. The rule — `ReplicatedKeyPlan::Rebind`

Given a stored row `e` and an incoming record `r` with the same `key_id`,
after the existing checks (byte-identical → `Unchanged`; a differing pubkey
half → `PubkeySwap`):

| # | condition | else |
|---|---|---|
| 1 | `e` is self-signed (`e.scrub_key_id == e.key_id`) | an anchor-scrubbed row is never rebound by its holder — that would shed the accord's scrub; role-gated records re-mint through genesis (#659's own ruling) → the existing `Downgrade` |
| 2 | `r` is self-signed (`r.scrub_key_id == r.key_id`) | a third party never rebinds a key; a self-signed → anchor-scrubbed record is the existing `Upgrade` path, untouched |
| 3 | `identity_type`, `identity_ref`, `valid_from`, `valid_until`, `roles`, `attestation_evidence` of `r` equal `e`'s | `RebindChangesRecord` (new): a rebind changes the claim's binding, never what is claimed — `identity_type` is authority-bearing, `roles` are lifted from the envelope, `valid_from` is history |
| 4 | `verify_envelope_binds_subject(e)` FAILS and `verify_envelope_binds_subject(r)` PASSES | `ConflictingVersion` (existing): unbound → bound is the only rebind. A bound row that differs from a bound record is the first-seen-wins case it always was; there is no "rebind a bound record", or first-seen-wins would collapse |
| 5 | `verify_key_registration(r)` — canonicalize, hash cross-check, Strict hybrid verify against `r`'s pubkeys, which by the pubkey-swap check are `e`'s | `UnverifiableSignature` (existing) — the holder proves possession of the key that is already registered |

All five hold → `Rebind`. Every reason is a `KeyRefusalReason`; the plan is
the one classifier and the backends carry the reason through (#565).

**The store step** (each backend, atomic, verify-before-mutation, the
`adopt_scrub_upgrade` shape): re-assert the guards in the `WHERE`
(`key_id`, `scrub_key_id = key_id`, `pubkey_ed25519_base64`, and the stored
`registration_envelope` bytes, so a concurrent rebind is a `Conflict`, not a
second write); `SET` only `registration_envelope`, `original_content_hash`,
`scrub_signature_classical`, `scrub_signature_pqc`, `scrub_timestamp`,
`pqc_completed_at`, `persist_row_hash` (recomputed), and **`mutated_at`** from
the same serve-position allocator admission uses, so `list_signed_key_records_since`
re-serves the row past any cursor that had passed it (V131's contract — the
bytes changed, so the position must). The wire index is rebuilt from the
STORED row (#640/#646). `admitted_at`, `valid_from`, `consent_role`, trust
columns: untouched.

**History.** The previous registration bytes are appended to
`federation_key_registration_history` (V148, append-only: `key_id`,
`registration_envelope`, `original_content_hash`,
`scrub_signature_classical`, `scrub_signature_pqc`, `scrub_key_id`,
`scrub_timestamp`, `replaced_at`, `replaced_by_hash`), read through
`list_key_registration_history(key_id)`. Folds and attestations key on
`key_id` and verify against pubkeys, which do not move, so they keep their
attester with or without this table; the table exists so the claim that was
replaced is auditable, and so a rebind is visibly a rebind rather than a
row that was always bound.

## 4. The doors

- **`Engine::rebind_key_record(signed: SignedKeyRecord) -> RebindOutcome`**
  (`Rebound | Unchanged | Refused { reason }`) and `PyEngine.rebind_key_record(json)`.
  Runs the plan; only `Rebind` (or `Unchanged`) proceeds; every other arm
  is returned as the typed refusal, never coerced into an `Insert` or an
  `Upgrade`. This is the door CIRISServer#606 calls with the owner's pen.
- **`Engine::rebind_self_federation_key(identity_type) -> RebindOutcome`**
  and the PyEngine mirror: builds the bound envelope for **this engine's own
  key** exactly as `register_self_federation_key` does
  (`bind_subject_into_envelope` over the composed signer's pubkeys), signs
  it hybrid, and routes it through the door above. This is what an agent
  runs at boot to heal one of the 529 empty-envelope records: the pen for an
  agent key is the agent's own signer. `register_self_federation_key` is
  unchanged — its `Conflict` on a differing row stays a refusal, because a
  registration door that silently rewrites rows is the wrong shape; the
  rebind is explicit.
- **Receive side.** `apply_replicated_key_record` gains the `Rebind` arm:
  the served record (the ordinary `Key` envelope, same kind, no policy-hash
  move) reaches a peer that holds the unbound row and heals it; a peer that
  never held it takes the `Insert` path, which already requires a bound,
  possession-proven record. `REPLICATION_POLICY_HASH` does not move.

## 5. Invariants

| # | invariant | falsified by | gate |
|---|---|---|---|
| I99 | The plan classifies: unbound self-signed row + bound self-signed same-pubkey same-claim record → `Rebind`; a differing pubkey half → `PubkeySwap`; a changed `identity_type` / `valid_from` / `roles` → `RebindChangesRecord`; bound row + bound differing record → `ConflictingVersion`; anchor-scrubbed row → `Downgrade`; an anchor-signed incoming → not `Rebind`; a bad signature → `UnverifiableSignature`. | a rebind that swaps a key, confers a role, or replaces an already-bound claim | plan fn, three backends |
| I100 | After `rebind_key_record`: the row's envelope binds the subject and `verify_key_registration` accepts it; `pubkey_*`, `valid_from`, `identity_type`, `admitted_at`, `consent_role` unchanged; `persist_row_hash` recomputed; the row is served by `list_signed_key_records_since` from a cursor that had already passed it; the history table holds the previous bytes; a second apply is `Unchanged`. | a rebound row invisible to a peer's cursor; history lost; a non-idempotent door | behavioural, three backends |
| I101 | Two nodes and a third: A holds the legacy unbound row and rebinds it through the door; B, holding the same legacy row, applies the served record → `Rebound` and then admits an attestation signed by the key at its federation-tier gate; C, never having held it, applies → `Inserted`. Before the rebind, B's and C's gates refused that attestation. | the identity round that never completes | behavioural, three engines |
| I102 | `rebind_self_federation_key` on an engine whose own row is unbound → `Rebound`; on a bound row → `Unchanged`; on an anchor-scrubbed row → `Refused{Downgrade}`. | an agent that cannot heal its own empty-envelope record | behavioural |
| I103 | The rebind rule is spelled once: every backend's store step is reached only through the plan's `Rebind` arm; no backend calls `verify_envelope_binds_subject` on the stored row itself; the PyO3 mirrors delegate to the Engine. | three spellings of the rule | from disk |

## 6. Not in scope

- **Rotation** (new pubkeys under the same `key_id`): by #659's own reasoning
  a different pubkey is a different identity. A rotation is a new key plus
  the existing owner-binding and occurrence doors.
- **Tolerating pre-#659 envelopes** at any gate: that reopens what #659 closed.
- **Anchor-scrubbed unbound rows**: re-minted through genesis, as #659 ruled.
