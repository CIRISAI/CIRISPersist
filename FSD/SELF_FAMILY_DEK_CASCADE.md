# FSD: At-Rest DEK Cascade — key_grant delivery for encrypted cohorts (CIRISPersist#152)

**Status:** implemented for the default tier (the substrate wraps). The zero-trust-of-host opt-in (§2) is not implemented.
**Normative anchor:** CEG §10.1.4 (substrate MUST wrap), §11.7.1 (Option-A forward secrecy), §8.1.12.4 (self DEK cascade), §8.1.13.3 (community DEK), §10.5.3 (epoch-DEK cascade), §5.6.8.4 (`key_grant` wire).
**Builds on:** `FSD/BLOB_ENCRYPTION_AT_REST.md` (at-rest content encryption) and the §10.5.3 epoch-DEK cascade (`list_key_grants_for_stream_epoch`). This FSD is the **per-recipient DEK delivery** layer, so cohort members *other than the writer* can decrypt.
**Related:** #161 Asks 4–5 (forward-secrecy producer gate), #183 (Self-at-login), #153 (at-rest half), #188 (negative-default dispatch).

---

## 0. Summary

`BLOB_ENCRYPTION_AT_REST.md` establishes that **persist encrypts content at rest** (master key, application layer, backend-agnostic). This FSD answers the question that layer leaves for the *shared* cohorts: when content lands at `cohort_scope: self | family`, **who wraps the content DEK to each recipient occurrence/member, and who re-wraps on membership change?**

**Answer: the substrate wraps.** This is the secrets-path model (persist AES-GCM-encrypts secrets at rest by *calling* CIRISVerify primitives — MISSION §1.4 forbids reimplementing crypto, not orchestrating it) applied to blob content. Producers do not each re-orchestrate the cascade; that would replicate a security-critical path across N consumers, the opposite of why the substrate exists. CEG §10.1.4 requires substrate-side wrap.

Persist owns both pieces the default tier needs: the **recipient enumeration** (`list_identity_occurrences_active` / `list_families_for_member_active`, #161) and the **wrap primitive** (the v2 recipient wrap in `ciris_crypto`). The cascade is "enumerate active recipients → wrap the DEK to each → record the `key_grant` rows."

### 0.4 Decisions

- **Who wraps.** The substrate, default tier (CEG §10.1.4). The secrets path (`src/secrets/crypto.rs` calling CIRISVerify under a hardware key) is the analogy.
- **Retroactive access on member ADD.** **self = yes** (an identity's occurrences must read its own self content). **family / community = the outcome of the `consensus_protocol` amendment that admits the member.** Node-core evaluates it (it owns `evaluate_consensus_protocol`); persist grants per the amendment result and has no second policy knob.
- **DEK on member REMOVE.** **Per-write fresh DEK** for self/family, so forward secrecy is automatic: a removed party keeps only the grants for content it already had and never gets new ones. No cross-content DEK reuse for self/family. Community uses the shared epoch DEK, rotated on membership change (§1.5).
- **The `get_blob_for_viewer` boundary.** Default tier: persist unwraps and returns plaintext. A zero-trust tier that returns the wrapped DEK + ciphertext for in-enclave unwrap is not implemented.

### 1.5 Three crypto tiers, one substrate primitive

The cohort scopes resolve to **three** at-rest postures (`CryptoTier`, CEG §8.1.13.3). This cascade is the substrate primitive shared by the two encrypted tiers.

| Tier (`CryptoTier`) | scope | recipients | DEK | holding claims | posture |
|---|---|---|---|---|---|
| **self / family** (`InvisibleEncrypted`) | `self`, `family` | `list_identity_occurrences_active` / `list_families_for_member_active` (#161) | **per-write**, fresh | placed at the content's own scope; reach only the cohort | **mandatory, no switch** (#827) |
| **Community** (`CommunityDek`) | `community`, `affiliations` | `resolve_community().members` | **shared per-community DEK** = the §10.5.3 **epoch-DEK cascade**, wrapped per member, rotated on membership change | within the roster, **with cleartext provenance** | **mandatory** (the DEK is community content's *sole* confidentiality boundary) |
| **Commons** (`Plaintext`) | `species`, `biosphere`, `federation`, and any unrecognized scope | — | none | at `federation` | plaintext |

- **The community DEK is not new crypto.** It is the §10.5.3 epoch-DEK cascade with the community roster as the subscriber set: *"a community is a stream its members subscribe to."* One shared DEK, wrapped per member on membership change.
- **`wrap_algorithm: v2` (hybrid x25519+ML-KEM) is mandatory on every encrypted path** — no v1 (CEG §8.1.12.4 / §8.1.13.3).
- **Provenance asymmetry:** community holding claims carry cleartext `attesting_key_id` + `community_key_id` + reason (non-member holders need them for keep/evict). Self/family content is structurally invisible: an outsider cannot discover the bytes exist (`is_structurally_invisible`).
- **Plaintext exceptions:** a `community` with `cohort_subkind: infrastructure` (`ciris-canonical` / governance — the trust root must be inspectable), the `public` room, and node→canonical conformance traces (`cohort_scope: federation`). CEG §8.1.13.3.

---

## 1. Why this exists

Structural invisibility (no outsider-visible holding claim for self/family) hides *existence* from federation peers. `BLOB_ENCRYPTION_AT_REST.md` adds confidentiality of *content* against the host (operator shell, lost device, leaked backup). Self/family content has a third requirement: **the user's *other* devices, and family members, must be able to read it.** A phone writes a `cohort_scope: self` note; the user's laptop and agent occurrence must decrypt it. That requires the content DEK delivered to each recipient — the §5.6.8.4 `key_grant` (HPKE-wrapped DEK per recipient pubkey).

Membership is not static (§11.7.1): a new occurrence is admitted (it must get retroactive grants for existing content), or one is revoked (it must stop receiving grants for *new* content — forward secrecy). #161 supplies revocation and the `list_*_active` enumeration; this FSD is the wrap and delivery that consume it.

## 2. Who wraps

**Default tier — the substrate wraps (host-trusted, defense-in-depth).** On a `cohort_scope: self | family` write, persist, inside the `put_blob_signing` content-encryption path:

1. generates a fresh content DEK and AES-GCM-encrypts the body into the at-rest envelope (`AtRestEnvelope`);
2. **enumerates active recipients** — `list_identity_occurrences_active(attesting_identity)` for `self`, `list_families_for_member_active(family_id)` for `family` (#161);
3. **wraps the DEK to each** recipient pubkey via the v2 recipient wrap (HPKE; hybrid x25519+ML-KEM) — *calling* the crypto authority, never reimplementing it (MISSION §1.4);
4. **records** the resulting `key_grant` rows, plus persist's own self-retention grant (`PERSIST_SELF_RECIPIENT`, the DEK wrapped under the content master key) so persist can serve the default-tier read.

A recipient occurrence with no published key is excluded, never granted (fail-secure), and surfaced as `hard_case:recipient_excluded`.

Consumers write `cohort_scope: self` and read back with `get_blob_for_viewer(sha, viewer_key_id)` — or the cohort-agnostic read door, which determines the path from the data — and deal with **no crypto**. This is the secrets-path posture (`src/secrets/crypto.rs`) generalized.

**Zero-trust-of-host tier (not implemented).** A consumer that requires the host to *never* hold the DEK would supply enclave-wrapped grants itself and persist would store them **opaque**, as the C3b stream cascade does. This is the only path where wrap orchestration would surface upward, and only for the consumer that asks for it.

**Why the substrate absorbs this.** The C3b streaming epoch-DEK cascade records opaque wraps and does not wrap — correct *there* (a high-throughput producer already managing epoch DEKs). Applying that to *all* self/family content would make every producer (agent, edge, lens) reimplement enumerate-wrap-cascade-on-change. The substrate's reason for being (MISSION §1.3, "lowest stateful substrate") is that consumers do not reimplement this. The host-trust cost (persist holds the DEK in the default tier) is the same trust model the secrets path already accepts.

## 3. Architecture (default tier)

- **Produce — the `put_blob_signing` cohort dispatch (three-way, negative-default, #188).** `self|family` → invisible-encrypt + per-write cascade; `community|affiliations` → community-DEK encrypt + provenance; **everything else → plaintext**. It is a negative default, *not* a scope allowlist: node-core's cohort vocabulary is richer (`species`/`planet`/`federation`/…), and an allowlist would leave new tiers unhandled. The plaintext exceptions are listed in §1.5. All encrypted paths use `wrap_algorithm: v2`.
- **Consume — `Engine::get_blob_for_viewer(sha, viewer_key_id) -> Vec<u8>` (+ PyO3).** Checks the viewer's grant (authorization), recovers the DEK through persist's self-retention grant, AES-GCM-decrypts. `NotGranted` if the viewer holds no grant (a revoked or never-member recipient, or one excluded at write); `NotHeld` if the bytes are absent.
- **Membership change.**
  - **ADD** → `Engine::rekey_self_occurrence_add` / `Engine::rekey_family_member_add`, run after the admission: for every existing at-rest blob of that self-collective or family, recover the DEK, wrap it to the newcomer's active occurrences, and record grants (retroactive access). Idempotent (re-running adds nothing) and fail-secure (a keyless newcomer occurrence is excluded). The family form emits one `hard_case:family_membership_change` per newcomer.
  - **REMOVE** → nothing is re-wrapped. Because the write-side enumeration in §2 reads `list_*_active`, a removed recipient drops out of the recipient set for every subsequent write — this is #161 Ask 4, and persist *enforces* it (not merely detects it) because persist is the one wrapping. Past grants are not revoked.

## 4. What this provides

- **#161 Asks 4–5** — "stop wrapping new `key_grant`s to a removed party" is §3 REMOVE plus the `list_*_active` enumeration in §2. Persist enforces it.
- **#183 (Self-at-login)** — the Self-DEK cascade to *both* the app and agent occurrences of one identity is §2 over `list_identity_occurrences_active`; an occurrence add is `rekey_self_occurrence_add`.
- **#153** — its at-rest half.

## 5. Open questions

- **Zero-trust-of-host tier.** The opaque-store path of §2 is not implemented.
