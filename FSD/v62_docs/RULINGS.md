# v62 rulings log

These are the decisions v62 is built to, with who made each. "Eric" is the project owner. "CC" is the CIRIS Constitution (v1.0-rc20, tag d4bd2a6) and its maintainers. "Verify" is CIRISVerify. "Kernel" is CIRISKernel. Items marked *next edition* are adopted as readings and will be written into the CC edition after rc20.

## Scope and sequencing

| Ruling | Source |
|---|---|
| v62 is the kernel refactor, started after the 61.4 LTS. Nothing urgent goes on 61.x unless it impacts Agent or Ratchet. | Eric |
| WASM/UEFI is in v62: one node module on native, a browser Dedicated Worker, and UEFI. Server's FSD WASM_NODE is the architecture. | Eric |
| The edition-2 cut ships IN v62; the JSON doors are shut, not deferred. | Eric |
| Persist owns CIRISKernel performance work. Upstream PR #3 landed as `kernel-v0.2.0`. | Eric |
| Verify versions are "minors until genesis". | Eric |

## The clean mesh (CC rc20, Eric)

- **Nothing carries.** The edition starts from a fresh `ceg-genesis-bundle/2` with no `prev`, signed by every holder. A node reads only edition 2. It refuses earlier-form objects and edition-1 row-refs by name. It is a wire break.
- **At upgrade, a node deletes its earlier store** (no archive, no held store) and keeps a local record of the counts only. A live legal hold stops the upgrade.
- **The schema is one edition-2 baseline** (V300). A node's storage layout is its own (CC 2.7.9).
- **Key liveness.**
  - Only an edition-2 `key:record` makes a key live, and holders carry their keys over themselves.
  - node/agent records end at most 365 days out; user and accord_holder records carry no end.
  - Three parties may end a key: the key itself, its owner, and the roster that seats it. No third party.
  - `act` is derived from the statements, never a payload member.
- **Composite signatures only.** There are no standalone component signers. The exceptions:
  - the per-chunk media trailer;
  - CC 6.1.3 substrate objects, for example the wholeness witness and the fountain aggregation meta.
- **`original_content_hash` is gone.**
- **identity_type is a set.** `user`/`accord_holder` never cohabit with `node`/`agent`, and `node` never with `agent`.
- **`canonical` is a ceremony conferral,** not a key type. `substrate_persist` is a key type that confers nothing.

## Genesis bundle/2 (CC 2.6.1.11; Verify's `edition2::genesis` reader)

- **What the bundle holds:**
  - it names rows by row id in `refs.also.cites`;
  - its payload is the charter: `recovery_commitments` keyed by holder identity-ref, `scope`, and optional `halt_fuse_secs`, `attach_window_secs` and witness members;
  - `holders` and `serve_nodes` are explicit sets;
  - the map is closed;
  - `iat` = floor(asserted_at / 1000);
  - a named row that is missing means Waiting.
- **Canonical standing** (ruling C): an identity-ref in `serve_nodes` of the bundle in force. An identity-ref names the key's genesis key and survives rotation.
- **The accord's proposal, participation and decision are gone.**
  - A roster change is a later bundle at the holders' count: a strict majority of the predecessor's holders, plus each added holder and each re-committed holder.
  - A recovery is a later bundle signed by the recovery key alone, changing only that seat.
  - A holder rotates only with its own statement under its current key.
- **Halt.**
  - One row with ONE composite statement from a SINGLE accord holder; no count.
  - The signer is judged against the holders of the bundle in force for `accord_root`.
  - With no bundle held, or an unknown kid, the halt WAITS. It is never refused while the roster is unknown.
  - `iss_not_holder` is refused.
  - The tokens are Verify's, as fixed in v23.3.0.
- **Lifecycle rows are counted,** with `refs {head, target}`.
- **Dedupe `invocation_id` and `nonce` within `valid_until`.** This is the store's duty; the token is `accord_invocation_replayed`.

## Families and payloads (*next edition* where marked)

- **Edition-2 payloads** for group:roster, membership, occurrence_revocation, cosign, revocation, takedown_notice, custody, key_grant and delivery_receipt carry the earlier record's members one to one as CDE, with no embedded signed object. The statements are the authority; a co-scrub is a counted voice. Persist's `edition2::payloads` is the source the CDDL will be written from. *next edition*
- **Composer rows** (`withdraws` / `recants` / `supersedes`) carry the TARGET row's family. A mismatch is refused as `composer_family_mismatch`. *next edition*
- **delegates_to families:**
  - capability, moderator, steward and guardianship → `self:delegates_to`;
  - owner binding → `ownership:{relation}:{target_kind}:{version}`, with the node's own statement as the second voice;
  - agent occurrence → `self:delegates_to:agent_occurrence`;
  - trust edges → `trust:{job}:{version}`.
- **Kinds:**
  - location proof is a ROW, `location_proof:v1`, signed by its subject only (its Verify family card is pending);
  - a touch claim is node-local;
  - a trust grant is a `delegates_to` row, and its revocation is the granter's `withdraws`;
  - a stream DEK is node-local, and its wraps are `key_grant:stream` rows;
  - a sealed manifest is unsigned blob bytes;
  - `trust:blessing` is a new family.
- **Planes:**
  - MESH: detection events, cirisnode attestations, receipts;
  - SPLIT: traces (`trace:complete:v1` replicates), fountain, the audit chain (local);
  - LOCAL: the Lens envelope, the secrets API.
- **Transport keys.** `transit_xwing_pubkey` and `onion_hop_xwing_pubkey` are one 1216-byte member each (pk_M ‖ pk_X). A seat's X-Wing key is live from the genesis binding or a counted `transport:canonical_rebind`; a seat publishing one alone is not live.

## Security fixes and corrections in v62

- **The infrastructure carve-out** (no steward binding, no moderator, plaintext, Commons replication) requires a conformant `infrastructure` record that is rooted in THIS node's trust set. Agents are never exempt. A serve-seat node needs an announced owner. No 61.x patch. (Eric)
- **Cycles.** No `delegates_to` is refused for closing a cycle; a walk visits each key once (CC 4.1.1 / 4.4.3.34). The kernel's `Graph::new` / `View::new` hang on a name cycle is fixed in kernel-v0.2.0. Every adapter path runs `layers::kept` and feeds only node-computed row ids.
- **Accord recovery** follows CC 4.2.6: a lineage walk by links; a spent commitment never returns; a recovery key is refused as a signing key by its public key material.

## Kernel departures adopted (all kernel-right)

- `reverse_quorum` and `custom:` are refused;
- `weighted` is read as whole numbers;
- an owner binding needs the node's cosignature (C557);
- a cycle is visited once;
- a fork is held as a tip. **Not yet switched:** this is kernel pass 2.
