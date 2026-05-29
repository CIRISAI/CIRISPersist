# Roadmap — CIRISPersist

**Status:** current as of **v3.0.0** (2026-05-28). Positions indicate
*sequence*, not dates — each milestone ships when its work is green.

CIRISPersist's 0.x → 2.x history — SQLite/Postgres parity, the
federation directory, CIRISVerify subsumption, the ~22-substrate
absorption of the agent's storage services, the change-feed, the
hash-chained audit log, hardware-backed secrets-at-rest, the
in-process cohabitation `Engine`, the federation cohabitation
capsule family (#109 / #111 / #115), and the CEG 0.2 substrate
conformance bundle (#116) — is recorded in
[`CHANGELOG.md`](../CHANGELOG.md). This document is the forward
roadmap from 3.0.

---

## 3.0 — Coherence Epistemic Graph 0.2 substrate conformance  *(this release)*

The milestone release that consolidates persist's substrate role
against CIRISRegistry's **Coherence Epistemic Graph 0.2** (commit
[`4b27130`](https://github.com/CIRISAI/CIRISRegistry/commit/4b27130)),
the spec that supersedes FSD-002. **Paired with CIRISVerify v4.0.0**
(the federation-wide CEG 0.2 wire alignment).

- **CIRISVerify pin v3.9.0 → v4.0.0** — federation-wide CEG 0.2
  wire alignment (`attestation:{mechanism}` strings; L1-L5 ladder
  officially consumer-side per CEG §8.1.9 Policy I).
- **CEG §6.1 — concurrent-write precedence + dedup triple**
  (`SUPERSEDES`/`WITHDRAWS`/`RECANTS`). Audit chain stores
  everything; reads project current effective state via
  `precedence_winner`.
- **CEG §7.0 — reserved-prefix admission rules + 0.1→0.2
  attestation-prefix dual-acceptance**. Typed
  `Error::ReservedPrefixEmitterMismatch`; new
  `identity_type::SUBSTRATE_PERSIST` / `WITNESS` constants.
- **CEG §10.1.2 — `holds_bytes` 24-hour TTL + ContentMiss feedback**.
  `list_holders` filters stale + withdrawn rows. No migration; TTL
  computed from `asserted_at`.
- **CEG §0.5 — fractal-self framing in `MISSION.md` §1.7**. Persist
  is relational fabric, not a Cartesian gate.

Carry-forward CEG closures from earlier 2.x cuts: typed Goal with
M-1 alignment (#114, 2.10.0), `occurrence_id` envelope fields
(#110, 2.9.0), `attestation_type` clean-break rename (#102, 2.4.0).

## 3.1 — CEG 0.3 retirement flip (planned)

Once CIRISRegistry retires the deprecated
`attestation:l{N}:*` form via the CEG §11.2 amendment process,
persist flips its admission policy from
`AttestationLadderTransitionPolicy::DualAccept` (3.0 default) to
`RejectDeprecated`. Small follow-up; the policy enum + flip target
are already documented + regression-tested.

## 3.x — Subscription v0.2 (CIRISPersist#84 substrate-wide)

The detection-events subscription that shipped in 2.13.0 (#113) is
the LensCore-scoped slice of persist's broader change-feed
ambition (#84). 3.x adds:

- `SubscriptionOptions` — configurable cadence, channel capacity,
  drop-on-full vs block-on-full policy.
- WAL-hook / LISTEN-NOTIFY producers for sub-second latency
  (current v0.1 is a 2-second poll).
- Per-substrate subscription primitives (audit, federation
  directory, ingest, blob_storage) — the umbrella that #84 named.

## 3.x — Encryption at Rest (carried over from 2.1)

Persist-managed, 100% backend-agnostic content encryption at rest —
the locked design in
[`FSD/ENCRYPTED_AT_REST.md`](../FSD/ENCRYPTED_AT_REST.md): encrypt
every substrate's content (AES-256-GCM via CIRISVerify) while
keeping a plaintext, signed, queryable projection. The capability —
a federation that measures reasoning quality without reading
reasoning content — is uniquely available to CIRIS because the
privacy boundary and the queryability boundary are the same
architectural line.

Six sequenced phases (FSD §9): V042-final shredding → `ReadEngine`
rewrite → ingest-path encrypt → read-path decrypt + signature
re-verify → migration of existing plaintext → docs/threat-model.
Gated on the nine boundary-map judgement calls (FSD §3.12).

## Beyond

- `lookup_trust_grant` projection: reconcile the
  `federation_trust_grants` chain-event-based projection with §6.1
  structural-composer rows so the trust-grant read path also
  applies precedence.
- `capacity:*` / `licensure:*` / `detection:*` admission carve-outs:
  the envelope-shape-based admission rules CEG §7.x defers to
  consumer composition. Substrate-level enforcement is a follow-up
  once the envelope contracts stabilize.
- Substrate coverage tracks the CIRISAgent absorption track to
  completion.

---

This document is rewritten when a milestone ships or the next is
scoped. If it drifts from [`CHANGELOG.md`](../CHANGELOG.md) and the
open issues, it is wrong — fix the document.
