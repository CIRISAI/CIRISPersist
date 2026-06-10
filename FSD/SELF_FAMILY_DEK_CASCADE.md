# FSD: At-Rest DEK Cascade — key_grant delivery for encrypted cohorts (CIRISPersist#152)

**Status:** **ACCEPTED — the 4-impl review converged on substrate-wraps-by-default (§2 / OQ-1).** CIRISAgent ✅ (consumer model), CIRISRegistry/CEG ✅ (conformant per §10.1.4 "substrate MUST wrap" + §8.1.12.4; surfaced two CEG fixes, shipped `b1ebb16`), CIRISNodeCore ✅ (both blob-facing surfaces stay crypto-free). **Scope expanded by CEG 0.16→0.17 (Registry#67, tag `v-ceg-0.17`): three crypto tiers, not two** — self/family + a *mandatory* community per-community-DEK tier that reuses the §10.5.3 epoch-DEK cascade persist already ships (C3b v4.3.0 / v4.4.0). See §1.5 + §7.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.8
**Created:** 2026-06-09 · **Accepted:** 2026-06-10
**Repo:** `~/CIRISPersist`
**Normative anchor:** CEG §10.1.4 (substrate MUST wrap), §11.7.1 (Option-A forward secrecy), §8.1.12.4 (self DEK cascade), §8.1.13.3 (community DEK), §10.5.3 (epoch-DEK cascade), §5.6.8.4 (`key_grant` wire). CEG 0.17.
**Builds on:** `FSD/ENCRYPTED_AT_REST.md` (the locked, unilateral at-rest content-encryption design) + the shipped §10.5.3 epoch-DEK cascade (`list_key_grants_for_stream_epoch`, v4.4.0). This FSD adds the **per-recipient DEK delivery** layer so cohort members *other than the writer* can decrypt.
**Driving context:** the keystone under **#161 Asks 4–5** (forward-secrecy producer gate), **#183** (Self-at-login), **#153's** remaining at-rest half, and the CEG-0.17 **community-at-rest** tier. Dispatch shape tracked on **#188** (negative-default, not an allowlist).

---

## 0.4 Review outcome (the converged decision)

**OQ-1 (who-wraps) — RESOLVED: the substrate wraps, default tier.** Unanimous across the panel — the producer-orchestrates alternative was rejected as security-critical-path duplication; the secrets-path precedent (`src/secrets/crypto.rs` calling CIRISVerify under a hardware key) is the right analogy, not C3b. CEG conformance confirmed: §10.1.4 *requires* substrate-side wrap.

**OQ-2 (retroactive access on member ADD):** **self = yes** (an identity's occurrences must read its own self content). **family / community = the outcome of the `consensus_protocol` amendment that admits the member** — node-core-evaluated (it owns `evaluate_consensus_protocol`); persist does not invent a second policy knob, it grants per the amendment result.

**OQ-3 (DEK on member REMOVE):** **per-write fresh DEK** — forward secrecy becomes automatic (a removed party keeps only the grants for content it already had; never gets new ones). No cross-content DEK reuse for self/family. (Community uses the shared epoch DEK, rotated on membership change — §1.5.)

**OQ-4 (`get_blob_for_viewer` hardware-unwrap boundary):** **one method with a mode flag** — default tier persist unwraps; zero-trust tier returns the wrapped DEK + ciphertext for in-enclave unwrap. Not on node-core's critical path (it composes the projection, not bytes).

## 0.5 / §1.5 — Three crypto tiers (CEG 0.17), one substrate primitive

Per CEG 0.17 (`v-ceg-0.17`) the cohort scopes resolve to **three** at-rest postures. #152's cascade is the substrate primitive shared by the two encrypted tiers (self/family per-write DEK; community shared epoch-DEK):

| Tier | scope | recipients | DEK | discovery | posture |
|---|---|---|---|---|---|
| **self / family** | `self`, `family` | `list_identity_occurrences_active` / `list_families_for_member_active` (#161) | **per-write**, fresh | suppressed (no `holds_bytes`) | **opt-in / default-off** (defense-in-depth over already-invisible bytes; v1 migration posture) |
| **Community** | `community`, `affiliations` | `resolve_community().members` | **shared per-community DEK** = the §10.5.3 **epoch-DEK cascade** (C3b, shipped), wrapped per-member only on membership change | `holds_bytes:*` **with cleartext provenance** | **mandatory** (the DEK is community content's *sole* confidentiality boundary) |
| **Commons** | `species`, `biosphere`, `federation` | — | none | `holds_bytes:*` plaintext | plaintext |

- **The community DEK is not new crypto** — it's `put_blob_signing` reusing the shipped §10.5.3 epoch-DEK cascade (`list_key_grants_for_stream_epoch`, v4.4.0) with the community roster as the subscriber set: *"a community is a stream its members subscribe to."* The CEG-0.15 "community per-member wrap is infeasible" concern was a misread; one shared DEK wrapped per-member only on membership change is feasible and shipped.
- **`wrap_algorithm: v2` (hybrid Ed25519+ML-DSA / x25519+ML-KEM) is mandatory on all three encrypted paths** — no v1 (the §8.1.12.4 / §8.1.13.3 fix from the Registry review).
- **Provenance asymmetry:** community emits `holds_bytes:*` carrying cleartext `attesting_key_id` + `community_key_id` + reason (non-member holders need it for keep/evict). self/family emit no `holds_bytes` at all.
- **Exceptions (plaintext Commons):** a `community` with `cohort_subkind: infrastructure` (`ciris-canonical` / governance — the trust root must be inspectable), and node→canonical conformance traces (`cohort_scope: federation`). §8.1.13.3 rulings.



## 0. TL;DR for reviewers

`ENCRYPTED_AT_REST.md` settled that **persist encrypts content at rest** (master-key, application-layer, backend-agnostic, sole-DB-opener → unilateral). This FSD answers the one question that layer left open for the *shared* cohorts: when content lands at `cohort_scope: self | family`, **who wraps the content DEK to each recipient occurrence/member, and who re-wraps on membership change?**

**The decision (§2): default = the substrate wraps; zero-trust-of-host = an opt-in where the producer wraps in a hardware enclave and persist stores the wrap opaque.** This is the secrets-path model (persist already AES-GCM-encrypts secrets at rest by *calling* CIRISVerify primitives — MISSION §1.4 forbids reimplementing crypto, not orchestrating it) generalized to blob content. It is **not** "every producer re-orchestrates the cascade" — that was an over-generalization of the C3b streaming precedent (corrected on #152), and it would replicate a security-critical path across N consumers, the opposite of why the substrate exists.

Persist already owns the two pieces the default tier needs: the **recipient enumeration** (`list_identity_occurrences_active` / `list_families_for_member_active`, shipped v4.8.0 / #161) and the **wrap primitive** (`ciris_verify_core` `wrap_dek_for_recipient`, exposed today as a stateless helper). The cascade is "enumerate active recipients → wrap the DEK to each → record the `key_grant` rows."

---

## 1. Why this exists

CEWP's structural-invisibility promise (no `holds_bytes:*` broadcast for self/family) hides *existence* from federation peers. `ENCRYPTED_AT_REST.md` adds confidentiality of *content* against the host (operator shell, lost device, leaked backup). But self/family content has a third requirement neither covers: **the user's *other* devices, and family members, must be able to read it.** A phone writes a `cohort_scope: self` note; the user's laptop + agent occurrence must decrypt it. That requires the content DEK delivered to each recipient — the §5.6.8.4 `key_grant` (HPKE-wrapped DEK per recipient pubkey).

And membership is not static (§11.7.1): a new occurrence is admitted (must get retroactive grants for existing content), or one is revoked (must stop receiving grants for *new* content — forward secrecy). #161 shipped the substrate's expression of revocation + the `list_*_active` enumeration; this FSD is the wrap/delivery that consumes it.

## 2. The who-wraps decision — **RESOLVED: substrate wraps, default tier** (see §0.4)

**Default tier — the substrate wraps (host-trusted, defense-in-depth).** On a `cohort_scope: self | family` write, persist (inside the `put_blob_signing` content-encryption path that `ENCRYPTED_AT_REST.md` already establishes):

1. generates / reuses the content DEK and AES-GCM-encrypts the body (existing at-rest path);
2. **enumerates active recipients** — `list_identity_occurrences_active(attesting_identity)` for `self`, `list_families_for_member_active(family_id)` for `family` (#161, v4.8.0);
3. **wraps the DEK to each** recipient pubkey via `ciris_verify_core::wrap_dek_for_recipient` (HPKE; v2 hybrid x25519+ML-KEM) — *calling* the CIRISVerify authority, never reimplementing (MISSION §1.4);
4. **records** the resulting `key_grant` rows (the existing `list_key_grants_for*` surface).

Consumers write `cohort_scope: self` and read back via a new `get_blob_for_viewer(sha, viewer_key_id)` — they deal with **zero crypto**. This is the secrets-path posture (`src/secrets/crypto.rs`) generalized.

**Opt-in tier — zero-trust-of-host (only when the consumer needs it).** A consumer that requires the host to *never* hold the DEK supplies enclave-wrapped grants itself (the stateless `wrap_dek_for_recipient` helper + the producer's hardware enclave) and persist stores them **opaque** — persist never sees the DEK, the C3b model. This is the *only* path where wrap-orchestration surfaces upward, and only for the consumer that asked.

**Why default-absorbs, not producer-orchestrates (the correction).** The C3b streaming epoch-DEK cascade locked "persist records opaque wraps, doesn't wrap" — correct *there* (a high-throughput producer already managing epoch DEKs). Generalizing it to *all* self/family content would make every producer (agent, edge, lens) reimplement enumerate-wrap-cascade-on-change — a security-critical path duplicated N times. The substrate's reason for being (MISSION §1.3, "lowest stateful substrate") is that consumers don't reimplement this. The host-trust cost (persist holds the DEK in the default tier) is a strict improvement over today's plaintext-at-rest and is the same trust model the secrets path already accepts; the stronger property is the opt-in tier.

## 3. Architecture (default tier)

- **`Ask 1` produce — `put_blob_signing` cohort branch (three-way, NEGATIVE-DEFAULT — #188).** The branch MUST be "`self|family` → invisible-encrypt + per-write cascade; `community|affiliations` → community-DEK encrypt + provenance `holds_bytes`; **everything else → plaintext**" — a negative default, *not* a scope allowlist (node-core's cohort vocab is richer: `species`/`planet`/`federation`/…; an allowlist leaves new tiers falling through unhandled). Exceptions route to plaintext: `cohort_subkind: infrastructure` communities + `cohort_scope: federation` conformance traces (§1.5). All encrypted paths use `wrap_algorithm: v2` (no v1).
- **`Ask 1` consume — `Engine.get_blob_for_viewer(sha, viewer_key_id) -> Bytes` (+ PyO3).** Looks up the latest `key_grant` for `(content_sha, viewer_key_id)`, unwraps the DEK (defer to the viewer's `ciris-keyring` hardware backend where present), AES-GCM-decrypts. Returns `NotGranted` if the viewer holds no grant (a revoked/never-member recipient).
- **`Ask 2` membership-change cascade (persist-driven in the default tier).** A background watcher (the `EvictionSweeper` pattern) observes occurrence/family admissions + revocations:
  - **ADD** → walk `cohort_scope: self|family` content for the affected identity/family, wrap the DEK to the new recipient, record grants (retroactive access).
  - **REMOVE** → **stop** wrapping for that recipient on subsequent content. Because the producer-side enumeration in §2.2 reads `list_*_active`, the removed recipient simply drops out of the recipient set — **this IS #161 Ask 4**, and persist can *enforce* it (not merely detect) precisely because persist is the one wrapping.

## 4. What it unblocks

- **#161 Asks 4–5** — the "stop wrapping new `key_grant`s to a removed party" gate is `§3 Ask 2 REMOVE` + the `list_*_active` enumeration in `§2.2`. Persist enforces it. Ask 5's `*_membership_change`-on-removal reserved-prefix emission rides the same watcher.
- **#183 (Self-at-login)** — the Self-DEK cascade to *both* the app and agent occurrences of one identity is exactly `§2` over `list_identity_occurrences_active`; the occurrence-withdraw re-key is `§3 Ask 2 REMOVE`.
- **#153** — closes its remaining at-rest half.

## 5. Open questions — **all RESOLVED by the review** (see §0.4 for the rationale)

- **OQ-1 — who wraps.** ✅ **Substrate, default tier** (CEG §10.1.4 requires it). Zero-trust-of-host is the opt-in.
- **OQ-2 — retroactive access on ADD.** ✅ **self = yes; family/community = the `consensus_protocol` amendment outcome** (node-core-evaluated). persist grants per the amendment result, no second policy knob.
- **OQ-3 — DEK on REMOVE.** ✅ **per-write fresh DEK** (self/family) → forward secrecy automatic. Community: shared epoch DEK rotated on membership change.
- **OQ-4 — `get_blob_for_viewer` boundary.** ✅ **one method, mode flag** (default = persist unwraps; zero-trust = returns wrapped DEK + ciphertext).
- **New (CEG 0.17): community-at-rest is mandatory, not opt-in** — the community DEK is the §10.5.3 epoch-DEK cascade with the roster as subscriber set; `holds_bytes` + cleartext provenance; `wrap_algorithm: v2`. Dispatch is negative-default (#188).

## 6. Phasing

| Phase | Work | Gate |
|---|---|---|
| 1 | This FSD + OQ resolution | ✅ **done** — review converged (substrate-wraps, three tiers) |
| 2 | Default-tier produce — `put_blob_signing` three-way negative-default dispatch (#188) + per-write self/family cascade (v2) + `get_blob_for_viewer` | `ENCRYPTED_AT_REST.md` at-rest layer |
| 3 | Community-DEK tier — reuse the §10.5.3 epoch-DEK cascade for `cohort_scope: community/affiliations` (roster = subscribers; `holds_bytes` + provenance) | Phase 2 |
| 4 | Membership-change watcher (`Ask 2`) = #161 Asks 4–5 enforcement + Self-at-login re-key (#183) | Phase 2 |
| 5 | Zero-trust-of-host opt-in (opaque-store path) | Phase 2 |

Phases 2–4 are the keystone for #161/#183. The community tier (Phase 3) is *mandatory* CEG-0.17 conformance, not additive.
