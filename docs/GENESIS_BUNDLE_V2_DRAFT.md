# SUPERSEDED: see the CC proposal

**This draft is superseded.** The `ceg-genesis-bundle/2` payload rule is now CIRISConstitution's proposal, built from this draft and agreed by persist. It lives at `rc20-review/genesis/PROPOSAL.md` (CIRISPersist#1274), and it differs from this draft as follows:
- `asserted_at`, not `produced_at`;
- no `count` or `trust_root` member;
- a `charter` sub-map;
- explicit `holders` and `serve_nodes` sets;
- a missing named row is Waiting;
- `onion_hop_xwing_pubkey` is required on a seat binding;
- the map is closed;
- `refs` is always present.

Persist builds no payload from either document until CC says the rule has landed. The text below is kept only as the record of what persist proposed.

---

# `ceg-genesis-bundle/2` payload: persist's PROVISIONAL draft

**Status: provisional, a proposal only.** The verifier and CC own this rule (CC 2.6.1.11, `signed_object_v2.tsv`, the CDDL; CEREMONY.md section 1 lists it as a precondition). Persist builds NO wire from this file. Persist v62 (slice E2a) builds only the generic parts, which hold whatever the member table becomes:
- the object statement verify (Verify 23.1.3 `verify_object_statement`);
- the object id;
- the first bundle has `version` 1 and no `refs.prev`;
- every listed holder signs the first bundle, counted against a held roster;
- a seat's X-Wing key is live from a binding row the bundle names.

Filed for CIRISPersist#1274. It is shaped to the four design rules the CC drafter stated:
- (1) rows are named in `refs` by row id, and the payload carries only charter parameters;
- (2) the bundle is a counted object;
- (3) the object id covers typ and payload, never a signature;
- (4) nothing waits inside it, and the verification order is stated.

## 1. The statement

Each holder's voice is one `ceg-object-statement` (CC 2.6.1.11):
- protected header `{1: -70100, 4: kid, 15: {1: iss, 6: iat, -70003: 2}, 16: "ceg-genesis-bundle/2"}`, with no `cty`, -70001 or -70002;
- `iss` is the holder's identity-ref, and `iat` is `floor(produced_at / 1000)`.

The bundle is **counted** (rule 2). It is N statements over ONE payload, byte for byte, one per holder. The payload carries **no `author`** (it is null in the object-id input), so every voice has the same object id.

## 2. Payload members (CDE map, CC 2.6.1.2)

| member | type | required_when | note |
|---|---|---|---|
| `"version"` | uint | always | 1 on the first bundle; prev's + 1 otherwise. A consistency check, never ranked (already in signed_object_v2.tsv). |
| `"refs"` | refs | on every bundle with a predecessor, and on the first (see below) | `prev`: the predecessor bundle's object id (absent on the first). The named rows are carried under `also` → `cites` (a set, CC 2.6.1.2); see section 3. Persist proposes no new `refs` member. An empty `refs` is refused, as CC 2.6.1.3 says. |
| `"produced_at"` | ms-time (uint) | always | The ceremony's instant, POSIX ms. `iat` derives from it. |
| `"holders"` | [* identity-ref] | always | A **set**: the accord holders this bundle seats, the roster the count reads. Each one's `key:record` is in `refs.also.cites`. |
| `"count"` | tstr | always | The charter's count rule for the NEXT bundle and for roster acts: `quorum:M/N` or `majority` (CC 4.4.3.6 arms). The first bundle is counted unanimously whatever this says (rule 2). |
| `"recovery_commitments"` | { + identity-ref => hash-digest } | always | One entry per holder in `holders`, keyed by the holder's identity-ref. The value is the CC 3.2 T3 commitment over the recovery key's public key material, as 32 bytes, never hex (CC 4.2.6: "a new one for every holder"). |
| `"halt_fuse_secs"` | uint | optional | Absent means 86400 (CC 4.2.1.1). Under the omit rule, a producer that writes 86400 keeps it. |
| `"family"` | tstr | always | The accord family id the roster is (`humanity-accord`): a name, not an anchor (CC 5.3.4). |
| `"trust_root"` | tstr | always | The trust-root community's id (`ciris-canonical`): a name, not an anchor. |

No member carries a signature, a key, a binding or a row's bytes (rule 1). Everything the bundle seats is a row of its own and is named by row id.

## 3. What `refs.also.cites` names (rule 1)

`refs.also.cites` is ONE set of row ids. It is sorted by deterministic encoding, with no duplicate. A reader types each named row from the row itself, never from position:

| named row | family | signer | what it gives |
|---|---|---|---|
| each holder's key record | `key:record`, `identity_type` [`accord_holder`], no `valid_until` | the holder | the holder's key is live |
| each seat's key record | `key:record`, [`node`], `valid_until` ≤ `asserted_at` + 31,536,000 s | the seat's key, offline | the seat's key is live |
| each seat's binding | `transport_destination` carrying `transit_xwing_pubkey` and `onion_hop_xwing_pubkey` (1216-byte bstr each), and NO v1 `transit_kex_pubkeys` | the seat's key | the seat's X-Wing keys, live from the genesis (section 5) |
| each seat's canonical conferral | the conferral row over the seat's key record (CC 4.2.1), counted | every holder (strict majority floor) | canonical standing |
| the trust-root community's founding record | its family | its founders, each signing | the community |

**Open (for CC):**
- Should the named set be split by role (for example `also.cites` for records and a new role for bindings), or stay one `cites` set with typing from the rows? This draft keeps one set, because CC 2.6.1.3 closes `also` at two roles.
- `onion_hop_xwing_pubkey` in the binding: rule 1 names it. Persist reads it today as an envelope member (slice E1).

## 4. The object id (rule 3)

`object_id = SHA-256(CDE(["CEG-object/2", "ceg-genesis-bundle/2", null, payload_bytes]))`. This is CC 2.6.1.11's object id with `author` null. It covers typ and payload, and no signature, `kid` or `iat`. So all N holder statements share one id, and that id is the pin (CC 5.3.4).

**Open (for CC):** `iat` sits in the protected header and is outside the id. Two holders whose clocks put different `iat`s on the same payload still give one id. That is consistent with rule 3, but the drafter should say so.

## 5. Verification order (rule 4: nothing waits inside it)

A reader holding the pin (or the holders' thumbprints), the bundle's N statements and the rows named in `refs.also.cites`:

1. Decode each statement strictly, and check its header (`verify_object_statement`). Refuse any statement whose payload bytes differ from the first's.
2. Compute the object id, then compare it to the pin. A mismatch makes the bundle void (CC 5.3.4).
3. Check the payload schema. `version` is 1 if and only if `refs.prev` is absent. `holders` is a non-empty set. `recovery_commitments` has exactly the holders' keys. `count` is a canonical arm.
4. Verify every named row with the bundle's rows as the ONLY key source. The holder key records are self-signed, so they need no outside key, which is why nothing waits. A named row that does not verify fails the bundle closed. A named row not supplied also fails the bundle closed, and never waits.
5. Count the voices. On the first bundle (no prev), every identity-ref in `holders` has exactly one statement verifying under its key record's key, and no other `iss` counts. On a later bundle, the voices of the previous bundle's `holders` meet the previous bundle's `count`.
6. Check each seat binding: it is signed by a seat whose key record is named, and its X-Wing halves pass the in-row separation (CC 3.3.6.2). Any failure fails the bundle closed.
7. Valid: the holders are seated, and each seat's X-Wing key is live from its binding. It moves only by a counted `transport:canonical_rebind` (CC 3.3.6.2, the rc20 ruling).

## 6. The revocation snapshot

The revocation snapshot's payload is NOT open in the same way. `signed_object_v2.tsv` rows 79–85 fix its members:
- `author`;
- `refs` (`prev`, `also.ack`);
- `seq`;
- `revoked` (a set of `[key, revocation, trusted_through]` entries).

What stays open there is the verifier's known-answer vectors (CC 2.6.1.12: "The vectors of the other signed objects, the genesis bundle and the revocation snapshot among them, are still the verifier's to publish").
