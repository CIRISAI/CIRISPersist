# FSD: Self/Family DEK Cascade — at-rest key_grant delivery for `cohort_scope: self | family` (CIRISPersist#152)

**Status:** **PROPOSED — needs the 4-impl nod on the who-wraps decision (§2).** This is a CEG-fabric architecture call (CIRISAgent / NodeCore / LensCore / Registry all read/write the same substrate), not a persist-internal one.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.8
**Created:** 2026-06-09
**Repo:** `~/CIRISPersist`
**Normative anchor:** CEG §11.7.1 (Option-A forward secrecy), §8.1.12.4 (self DEK cascade), §5.6.8.4 (`key_grant` wire).
**Builds on:** `FSD/ENCRYPTED_AT_REST.md` (the locked, unilateral at-rest content-encryption design — persist is the sole DB opener and encrypts content under a master key, keeping a scoreable projection). This FSD adds the **per-recipient DEK delivery** layer for the `self`/`family` cohorts, so occurrences/members *other than the writer* can decrypt.
**Driving context:** the keystone under **#161 Asks 4–5** (forward-secrecy producer gate), **#183** (Self-at-login Self-DEK cascade + occurrence re-key), and **#153's** remaining at-rest half. Resolving §2 unblocks all three.

---

## 0. TL;DR for reviewers

`ENCRYPTED_AT_REST.md` settled that **persist encrypts content at rest** (master-key, application-layer, backend-agnostic, sole-DB-opener → unilateral). This FSD answers the one question that layer left open for the *shared* cohorts: when content lands at `cohort_scope: self | family`, **who wraps the content DEK to each recipient occurrence/member, and who re-wraps on membership change?**

**The decision (§2): default = the substrate wraps; zero-trust-of-host = an opt-in where the producer wraps in a hardware enclave and persist stores the wrap opaque.** This is the secrets-path model (persist already AES-GCM-encrypts secrets at rest by *calling* CIRISVerify primitives — MISSION §1.4 forbids reimplementing crypto, not orchestrating it) generalized to blob content. It is **not** "every producer re-orchestrates the cascade" — that was an over-generalization of the C3b streaming precedent (corrected on #152), and it would replicate a security-critical path across N consumers, the opposite of why the substrate exists.

Persist already owns the two pieces the default tier needs: the **recipient enumeration** (`list_identity_occurrences_active` / `list_families_for_member_active`, shipped v4.8.0 / #161) and the **wrap primitive** (`ciris_verify_core` `wrap_dek_for_recipient`, exposed today as a stateless helper). The cascade is "enumerate active recipients → wrap the DEK to each → record the `key_grant` rows."

---

## 1. Why this exists

CEWP's structural-invisibility promise (no `holds_bytes:*` broadcast for self/family) hides *existence* from federation peers. `ENCRYPTED_AT_REST.md` adds confidentiality of *content* against the host (operator shell, lost device, leaked backup). But self/family content has a third requirement neither covers: **the user's *other* devices, and family members, must be able to read it.** A phone writes a `cohort_scope: self` note; the user's laptop + agent occurrence must decrypt it. That requires the content DEK delivered to each recipient — the §5.6.8.4 `key_grant` (HPKE-wrapped DEK per recipient pubkey).

And membership is not static (§11.7.1): a new occurrence is admitted (must get retroactive grants for existing content), or one is revoked (must stop receiving grants for *new* content — forward secrecy). #161 shipped the substrate's expression of revocation + the `list_*_active` enumeration; this FSD is the wrap/delivery that consumes it.

## 2. The who-wraps decision (the call this FSD exists to settle)

**Default tier — the substrate wraps (host-trusted, defense-in-depth).** On a `cohort_scope: self | family` write, persist (inside the `put_blob_signing` content-encryption path that `ENCRYPTED_AT_REST.md` already establishes):

1. generates / reuses the content DEK and AES-GCM-encrypts the body (existing at-rest path);
2. **enumerates active recipients** — `list_identity_occurrences_active(attesting_identity)` for `self`, `list_families_for_member_active(family_id)` for `family` (#161, v4.8.0);
3. **wraps the DEK to each** recipient pubkey via `ciris_verify_core::wrap_dek_for_recipient` (HPKE; v2 hybrid x25519+ML-KEM) — *calling* the CIRISVerify authority, never reimplementing (MISSION §1.4);
4. **records** the resulting `key_grant` rows (the existing `list_key_grants_for*` surface).

Consumers write `cohort_scope: self` and read back via a new `get_blob_for_viewer(sha, viewer_key_id)` — they deal with **zero crypto**. This is the secrets-path posture (`src/secrets/crypto.rs`) generalized.

**Opt-in tier — zero-trust-of-host (only when the consumer needs it).** A consumer that requires the host to *never* hold the DEK supplies enclave-wrapped grants itself (the stateless `wrap_dek_for_recipient` helper + the producer's hardware enclave) and persist stores them **opaque** — persist never sees the DEK, the C3b model. This is the *only* path where wrap-orchestration surfaces upward, and only for the consumer that asked.

**Why default-absorbs, not producer-orchestrates (the correction).** The C3b streaming epoch-DEK cascade locked "persist records opaque wraps, doesn't wrap" — correct *there* (a high-throughput producer already managing epoch DEKs). Generalizing it to *all* self/family content would make every producer (agent, edge, lens) reimplement enumerate-wrap-cascade-on-change — a security-critical path duplicated N times. The substrate's reason for being (MISSION §1.3, "lowest stateful substrate") is that consumers don't reimplement this. The host-trust cost (persist holds the DEK in the default tier) is a strict improvement over today's plaintext-at-rest and is the same trust model the secrets path already accepts; the stronger property is the opt-in tier.

## 3. Architecture (default tier)

- **`Ask 1` produce — `put_blob_signing` cohort branch.** `self|family` → encrypt + cascade (steps §2.1–4). `community|partnered|global` → status quo (community content federates plaintext per CEG 0.8, no suppression, no cascade — confirmed #154).
- **`Ask 1` consume — `Engine.get_blob_for_viewer(sha, viewer_key_id) -> Bytes` (+ PyO3).** Looks up the latest `key_grant` for `(content_sha, viewer_key_id)`, unwraps the DEK (defer to the viewer's `ciris-keyring` hardware backend where present), AES-GCM-decrypts. Returns `NotGranted` if the viewer holds no grant (a revoked/never-member recipient).
- **`Ask 2` membership-change cascade (persist-driven in the default tier).** A background watcher (the `EvictionSweeper` pattern) observes occurrence/family admissions + revocations:
  - **ADD** → walk `cohort_scope: self|family` content for the affected identity/family, wrap the DEK to the new recipient, record grants (retroactive access).
  - **REMOVE** → **stop** wrapping for that recipient on subsequent content. Because the producer-side enumeration in §2.2 reads `list_*_active`, the removed recipient simply drops out of the recipient set — **this IS #161 Ask 4**, and persist can *enforce* it (not merely detect) precisely because persist is the one wrapping.

## 4. What it unblocks

- **#161 Asks 4–5** — the "stop wrapping new `key_grant`s to a removed party" gate is `§3 Ask 2 REMOVE` + the `list_*_active` enumeration in `§2.2`. Persist enforces it. Ask 5's `*_membership_change`-on-removal reserved-prefix emission rides the same watcher.
- **#183 (Self-at-login)** — the Self-DEK cascade to *both* the app and agent occurrences of one identity is exactly `§2` over `list_identity_occurrences_active`; the occurrence-withdraw re-key is `§3 Ask 2 REMOVE`.
- **#153** — closes its remaining at-rest half.

## 5. Open questions for the 4-impl review

- **OQ-1 — who wraps (the §2 decision).** Default-absorbs vs. producer-orchestrates. This FSD argues default-absorbs with a zero-trust-of-host opt-in. **Needs the agent / NodeCore / LensCore / Registry nod.**
- **OQ-2 — does the membership-ADD retroactive cascade run in the default tier, or is retroactive access deliberately *not* granted** (forward-secrecy-symmetric: a new member sees only content from after they joined)? §11.7.1 says removed parties *retain* historical grants; it is silent on whether *new* members *gain* historical access. Default proposal: cascade retroactively for `self` (it's the same user's devices), gate behind family `consensus_protocol` for `family`.
- **OQ-3 — DEK lifecycle on REMOVE.** Forward secrecy stops *new* wraps; does it also *rotate* the DEK for *future* content (so the removed party's retained grant can't decrypt new content sharing an old DEK)? Proposal: per-write fresh DEK (no cross-content DEK reuse) makes this automatic — the removed party's grant only ever decrypted the content it was granted.
- **OQ-4 — `get_blob_for_viewer` hardware-unwrap boundary.** Default tier: persist can unwrap (it holds the DEK). Zero-trust tier: persist returns the wrapped DEK + ciphertext and the viewer unwraps in-enclave. One method with a mode flag, or two methods?

## 6. Phasing

| Phase | Work | Gate |
|---|---|---|
| 1 | This FSD + OQ resolution | the 4-impl nod on §2 / OQ-1 |
| 2 | Default-tier produce (`Ask 1` encrypt + cascade) + `get_blob_for_viewer` | Phase 1 + `ENCRYPTED_AT_REST.md` Phase landed |
| 3 | Membership-change watcher (`Ask 2`) = #161 Ask 4–5 enforcement | Phase 2 |
| 4 | Zero-trust-of-host opt-in (opaque-store path) | Phase 2 |

Phases 2–3 are the keystone for #161/#183. Phase 4 is additive.
