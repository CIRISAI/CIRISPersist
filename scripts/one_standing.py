#!/usr/bin/env python3
"""one_standing.py: who stands where, and how many must agree, is answered
in a closed set of places (no cargo).

    scripts/one_standing.py check        exit 1 on a new site, a grown site or a stale entry
    scripts/one_standing.py list         every site found, as RATCHET lines (to paste after a shrink)
    scripts/one_standing.py --self-test  the gate's own witnesses

v62.0.0 (SD-fix2; CLEAN-standing.md §6). The audit found "who holds a duty"
answered five ways, the bundle's holders read by three copies, five parsers
of `quorum:M/N`, seven have/need result shapes, and a room's duty walk that
read its edges timelessly (SD-fix1). Each of these questions is to collapse
onto ONE `standing::` reader. Until it does, this gate is a RATCHET: every
site that answers one of the questions today is listed in RATCHET below, by
(rule, file, enclosing fn) with its count. The gate is red when:

  - a site appears in a (rule, file, fn) not listed: a NEW copy;
  - a listed (rule, file, fn) has MORE sites than its count: a copy grew;
  - a listed entry has FEWER sites than its count, or none: the ratchet
    must be lowered in the same change (so the list only shrinks and never
    outlives its sites).

Production code only: comments, literals and test-gated code are blanked by
`earlier_form_doors.Tree` (and `feature = "test-anchor"` code is test code,
as `one_threshold.py` reads it).

The seven rules (CLEAN-standing.md §6):

  founder     the member role `MEMBER_ROLE_FOUNDER` is compared (a founder
              is a ROLE; duty holding is `duty_holders`, CC 4.5.4).
  bundle      the genesis bundle's holders are read (`genesis_in_force(`,
              `.holders()`, `.is_holder(`, `.halt_roster(`) outside
              `edition2/genesis.rs`.
  walk        a delegation walker is called (`scoped_delegation_reach*`,
              `issuer_reaches_target_via_scoped_delegation`,
              `enumerate_scoped_delegation_reach`, `moderation_reach_of_at*`).
              Each ratchet entry is tagged with the question it answers.
  walk-instant  inside a MAY-ACT fn (MAY_ACT below: a room duty judged for
              an act), a walk that does not read its edges at the act's
              instant: a call to a timeless wrapper, or a
              `scoped_delegation_reach_in(..)` whose last argument
              (`act_at`) is `None`. NOT a ratchet: red at every site (SD-fix1
              CC 4.5.5 "Authority is judged over the act's own causal past").
  protocol    `quorum:M/N` is parsed (`strip_prefix("quorum:")` or
              `strip_prefix(..QUORUM_PREFIX)`).
  present     a decision fn (`check_*`, `*_admission`, `*_verdict`) reads a
              roster at the host's clock (`effective_roster(`,
              `active_community_members(`, `active_family_members(`).
  label       a reserved role is read off a key's own `identity_type`
              (`ACCORD_HOLDER` / `WISE_AUTHORITY` in a `claims_role(`,
              `set_contains(`, `contains(` or `==`) — CC rc20 3.4.7: "No
              admission decision reads it to open a reserved family."
  count-shape a struct carrying both a `required|need` field and a
              `roster_size|of|n` field (a have/need/of result shape).
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import earlier_form_doors as efd  # noqa: E402

DECISION_FN = re.compile(r"^check_|_admission$|_verdict$")

# (file, fn): the room-duty fns that judge an ACT (walk-instant rule).
MAY_ACT = {
    ("src/federation/admission.rs", "is_named_moderator"),
    ("src/federation/admission.rs", "moderators_of"),
    ("src/federation/admission.rs", "check_moderation_admission"),
}
TIMELESS_WALKERS = ("scoped_delegation_reach", "issuer_reaches_target_via_scoped_delegation",
                    "enumerate_scoped_delegation_reach")

RULES: dict[str, re.Pattern] = {
    "founder": re.compile(r"\bMEMBER_ROLE_FOUNDER\b"),
    "bundle": re.compile(r"\bgenesis_in_force\s*\(|\.holders\(\s*\)|\.is_holder\s*\(|\.halt_roster\s*\("),
    "walk": re.compile(
        r"(?<!fn )\b(?:scoped_delegation_reach(?:_at|_in)?|issuer_reaches_target_via_scoped_delegation"
        r"|enumerate_scoped_delegation_reach|moderation_reach_of_at(?:_within)?)\s*(?:::<[^>]*>)?\s*\("),
    "protocol": re.compile(r"\bstrip_prefix\s*\("),
    "present": re.compile(r"(?<!fn )\b(?:effective_roster|active_community_members|active_family_members)\s*\("),
    "label": re.compile(
        r"\b(?:claims_role|set_contains|contains)\s*\([^;{}]{0,160}?\b(?:ACCORD_HOLDER|WISE_AUTHORITY)\b"
        r"|==\s*[\w:]*\b(?:ACCORD_HOLDER|WISE_AUTHORITY)\b"),
}
STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_]\w*)\s*(?:<[^>{]*>)?\s*\{")
FIELD_RE = re.compile(r"(?:^|[,{\n])\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:", re.M)
NEED_FIELDS = {"required", "need"}
OF_FIELDS = {"roster_size", "of", "n"}

# (rule, file, fn): (count, why). Generated by `list` at the root passes' end
# tree 46157719 (+ SD-fix1); SHRINK ONLY.
RATCHET: dict[tuple[str, str, str], tuple[int, str]] = {
    ('bundle', 'src/ceremony.rs', 'import_offer_into_throwaway'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/engine.rs', '<top>'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/engine.rs', 'canonical_bootstrap_hints'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/engine.rs', 'genesis_in_force'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/engine.rs', 'report_genesis_at_boot'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/admission.rs', 'accord_holder_roster'): (1, 'copy 1 of the in-force holders (same body as bundle_holder_refs); CLEAN S1'),
    ('bundle', 'src/federation/admission.rs', 'canonical_conferral_coscrub'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/admission.rs', 'duty_holders_for_federation'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/admission.rs', 'root_grant_reading'): (1, "KR-fix2: the named bundle's state for a root grant (bundle_holders(Named)); kept with S1"),
    ('bundle', 'src/federation/admission.rs', 'root_grant_voice_parties'): (1, 'KR-fix2: holders of the named bundle as voice parties; -> standing::bundle_holders(Named) (CLEAN S1)'),
    ('bundle', 'src/federation/admission.rs', 'check_root_grant_counted'): (1, "KR-fix4 (pass 4s): the gate's no-holder refusal reads the NAMED bundle's holders (genesis_in_force + bundle_holders); -> standing::bundle_holders(Named) (CLEAN S1)"),
    ('bundle', 'src/federation/admission.rs', 'check_root_voice_signer'): (1, "KR-fix4 (pass 4s): the door's voice-signer check reads the NAMED bundle's holders (genesis_in_force + bundle_holders); -> standing::bundle_holders(Named) (CLEAN S1)"),
    ('bundle', 'src/federation/canonical_community.rs', 'check_attach_freshness'): (1, 'KB-fix1: attach freshness reads the in-force state; -> holders_in_force (CLEAN S1)'),
    ('bundle', 'src/federation/edition2/accord_rescan.rs', 'accord_root_not_held'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/accord_rescan.rs', 'rescan_needed'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/halt.rs', 'put_lifecycle_at'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/halt.rs', 'roster_in_force'): (2, 'the halt roster in force (a reader, kept as the halt seam)'),
    ('bundle', 'src/federation/edition2/occurrence.rs', 'bind_xwing_keys_for'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/occurrence.rs', 'onion_hop_xwing_pubkey_for'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/peer_rooting.rs', 'peer_rooting'): (2, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/recovery_signer.rs', 'recovery_keys_in_force'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/signing_domain.rs', 'signer_standing'): (2, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/signing_domain.rs', 'verify_accord_manifest_v2'): (2, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/signing_domain.rs', 'verify_identity_template_v1'): (2, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/standing.rs', 'holds_accord_standing'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/transport_rebind.rs', 'put_rebind_voice'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/transport_rebind.rs', 'rebind_counted'): (1, 'KR-fix2: re-bind counted over the NAMED bundle; -> standing::bundle_holders(Named) (CLEAN S1)'),
    ('bundle', 'src/federation/edition2/transport_rebind.rs', 'rebind_held_for'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/transport_rebind.rs', 'rebind_voice_parties'): (1, 'KR-fix2: re-bind voice parties over the named bundle; CLEAN S1'),
    ('bundle', 'src/federation/edition2/trust_root_group.rs', 'holder_founder_counts_at'): (2, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/edition2/trust_root_group.rs', 'holders_in_force'): (1, 'THE in-force holders seam (KR-fix2; KB-fix1 routes every holder reader here): the S1 target, kept'),
    ('bundle', 'src/federation/edition2/trust_root_group.rs', 'is_bundle_holder'): (1, 'copy 3 (bool); CLEAN S1'),
    ('bundle', 'src/federation/genesis/posture.rs', 'bundle_in_force'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/self_at_login.rs', 'transit_kex_pair_for'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/self_at_login.rs', 'transit_xwing_pubkey_for'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/federation/trust_root.rs', 'bundle_root_holders'): (1, "KB-fix1's root-holders reader over the in-force tips; -> holders_in_force (CLEAN S1)"),
    ('bundle', 'src/federation/trust_root.rs', 'transit_eligibility_by_consent'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/ffi/pyo3.rs', 'canonical_bootstrap_hints'): (2, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/ffi/pyo3.rs', 'close_blocking'): (1, "not a bundle: the Python runtime's holder count"),
    ('bundle', 'src/ffi/pyo3.rs', 'report_genesis_at_boot'): (1, "reads the bundle's holders inline; -> standing::bundle_holders (CLEAN S1)"),
    ('bundle', 'src/ffi/pyo3.rs', 'reset_engine'): (1, "not a bundle: the Python runtime's holder count"),
    ('count-shape', 'src/federation/ownership_reclaim.rs', 'WaQuorum'): (1, 'a have/need/of result shape; -> standing::Count (CLEAN S3)'),
    ('count-shape', 'src/federation/reverse_quorum.rs', 'DismissalQuorum'): (1, 'a have/need/of result shape; -> standing::Count (CLEAN S3)'),
    ('count-shape', 'src/federation/reverse_quorum.rs', 'ReverseQuorumFold'): (1, "the reverse-quorum fold's output (thresholds map to need(Reverse); the fold stays)"),
    ('count-shape', 'src/federation/trust_root.rs', 'SignerCount'): (1, 'a have/need/of result shape; -> standing::Count (CLEAN S3)'),
    ('count-shape', 'src/kernel/view.rs', 'SeatFields'): (1, "the kernel's seat row fields, not a tally (kept)"),
    ('founder', 'src/federation/admission.rs', 'check_infrastructure_consensus_protocol'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'check_infrastructure_founder_count_unchanged'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'check_infrastructure_quorum_strict_majority'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'community_authority_set_for'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'founders_not_node_verdict'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'infrastructure_conformance'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'is_conformant_infrastructure_record'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'licence_roots_at'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'moderation_duty_roots'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/admission.rs', 'no_moderator_verdict'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/affiliation_config.rs', 'deciding_seats'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/canonical_community.rs', 'check_trust_root_roster_change'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/canonical_community.rs', 'envelope_founders'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/canonical_community.rs', 'founders'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/canonical_community.rs', 'resolve_community'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/canonical_community.rs', 'verify_founders_link_memo'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/consensus.rs', '<top>'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/consensus.rs', 'is_founder'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/edition2/group_serve.rs', 'group_servable'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/membership_acceptance.rs', 'check_proposer_under_founder_only'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/membership_acceptance.rs', 'check_standing_proposal'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/mod.rs', 'check_roster_authority_over'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/mod.rs', 'founder_candidates'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/mod.rs', 'prepare_roster_events'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/mod.rs', 'roster_event_verdict'): (2, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/federation/public_room.rs', 'live_standing_proposal'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/kernel/consensus.rs', 'ballot_rows'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('founder', 'src/kernel/consensus.rs', 'count_over'): (1, 'role founder compared; duty uses go with DC-fix2d-2, room authority / T7 stay (ruled)'),
    ('label', 'src/federation/admission.rs', 'admission_unit_voice_parties'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/admission.rs', 'check_peer_record_admission'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/admission.rs', 'check_reserved_prefix_admission'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/admission.rs', 'is_conformant_infrastructure_record'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/edition2/admission_unit.rs', 'live_person_voices'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/edition2/occurrence.rs', 'is_person'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/edition2/signing_domain.rs', 'signer_standing'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/hardware_attestation.rs', 'admit_key_record'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/ownership_reclaim.rs', 'wa_quorum_over_body'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/federation/register.rs', 'record_is_role_gated'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('label', 'src/ffi/directory_capsule.rs', 'list_keys_by_identity_type'): (1, 'reads a reserved role off identity_type; CC rc20 3.4.7 (CLEAN S9 triage)'),
    ('present', 'src/federation/admission.rs', 'no_moderator_verdict'): (1, 'decision reads the roster at the host clock; -> standing::roster(G, act instant) (CLEAN S4)'),
    ('present', 'src/federation/canonical_community.rs', 'check_trust_root_roster_change'): (1, 'decision reads the roster at the host clock; -> standing::roster(G, act instant) (CLEAN S4)'),
    ('present', 'src/federation/group_plane.rs', 'check_cosigned_withdraws'): (2, 'decision reads the roster at the host clock; -> standing::roster(G, act instant) (CLEAN S4)'),
    ('present', 'src/federation/membership_acceptance.rs', 'check_proposer_under_founder_only'): (2, 'decision reads the roster at the host clock; -> standing::roster(G, act instant) (CLEAN S4)'),
    ('present', 'src/federation/membership_acceptance.rs', 'check_standing_proposal'): (1, 'decision reads the roster at the host clock; -> standing::roster(G, act instant) (CLEAN S4)'),
    ('protocol', 'src/federation/admission.rs', 'infrastructure_quorum'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/federation/canonical_community.rs', 'check_trust_root_shape'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/federation/canonical_community.rs', 'parse_quorum'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/federation/consensus.rs', 'evaluate_counted'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/federation/consensus.rs', 'required_signatures_at'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/federation/group_membership_change.rs', 'parse_quorum_protocol'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/federation/reverse_quorum.rs', 'parse'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/federation/types.rs', 'is_canonical_form'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('protocol', 'src/kernel/consensus.rs', 'arm_over'): (1, 'parses quorum:M/N; -> standing::parse_protocol (CLEAN S2)'),
    ('walk', 'src/federation/admission.rs', 'check_moderation_admission'): (1, 'may-act (room duty); act_at checked by walk-instant'),
    ('walk', 'src/federation/admission.rs', 'consent_revocation_reach'): (1, 'consent proxy (rule 3); stays a walk'),
    ('walk', 'src/federation/admission.rs', 'emitter_resolves_to_authority'): (1, 'licence issuance; stays a walk'),
    ('walk', 'src/federation/admission.rs', 'holds_grant_delegation'): (1, 'owner key-grant custody; stays a walk'),
    ('walk', 'src/federation/admission.rs', 'is_named_moderator'): (1, 'may-act (room duty); act_at checked by walk-instant'),
    ('walk', 'src/federation/admission.rs', 'issuer_reaches_target_via_scoped_delegation'): (1, 'generic wrapper (timeless)'),
    ('walk', 'src/federation/admission.rs', 'licensure_issuance_at'): (1, 'licence issuance; stays a walk'),
    ('walk', 'src/federation/admission.rs', 'moderation_reach_of_at'): (1, 'roster fold (#908); -> standing::holders (CLEAN S7)'),
    ('walk', 'src/federation/admission.rs', 'moderation_reach_of_at_within'): (1, 'roster fold (#908); -> standing::holders (CLEAN S7)'),
    ('walk', 'src/federation/admission.rs', 'moderators_of'): (1, 'may-act (room duty); act_at checked by walk-instant'),
    ('walk', 'src/federation/admission.rs', 'quorum_licence_reach'): (1, 'licence issuance; stays a walk'),
    ('walk', 'src/federation/admission.rs', 'reachable_under_scope'): (1, 'generic host reachability; not an authority decision'),
    ('walk', 'src/federation/admission.rs', 'reachable_under_scope_with_reasons'): (2, 'generic host reachability; not an authority decision'),
    ('walk', 'src/federation/admission.rs', 'scoped_delegation_reach'): (1, 'the timeless generic wrapper'),
    ('walk', 'src/federation/admission.rs', 'scoped_delegation_reach_in'): (1, 'the lens wrapper (SD-fix1 act_at)'),
    ('walk', 'src/federation/mod.rs', 'moderator_roots_at'): (1, 'holders copy 5 (roster fold); -> standing::holders (CLEAN S7)'),
    ('walk', 'src/federation/mod.rs', 'prepare_roster_events'): (1, 'holders copy 4 (steward tier at now); -> standing::holders (CLEAN S7)'),
}


def root() -> Path:
    return Path(os.environ.get("ONE_STANDING_ROOT") or Path(__file__).resolve().parent.parent)


def fn_spans(code: str) -> list[tuple[int, int, str]]:
    spans = []
    for m in efd.FN_RE.finditer(code):
        body = efd.block_body(code, m.end())
        if body:
            spans.append((body[0], body[1], m.group(1)))
    return spans


def enclosing(spans: list[tuple[int, int, str]], at: int) -> str:
    best, width = "<top>", None
    for a, b, name in spans:
        if a <= at <= b and (width is None or b - a < width):
            best, width = name, b - a
    return best


def call_args(code: str, open_paren: int) -> list[str]:
    """Top-level comma-split arguments of the call whose `(` is at
    `open_paren`."""
    depth, k, start, out = 0, open_paren, open_paren + 1, []
    while k < len(code):
        ch = code[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                out.append(code[start:k])
                break
        elif ch == "," and depth == 1:
            out.append(code[start:k])
            start = k + 1
        k += 1
    return [a.strip() for a in out if a.strip()]


def sites(base: Path) -> tuple[dict[tuple[str, str, str], int], list[str]]:
    """Every (rule, file, fn) with its count, and the non-ratchet reds."""
    tree = efd.Tree(base, anchored=True)
    found: dict[tuple[str, str, str], int] = {}
    hard: list[str] = []

    def add(rule: str, rel: str, fn: str) -> None:
        found[(rule, rel, fn)] = found.get((rule, rel, fn), 0) + 1

    for rel in tree.glob("src/**/*.rs"):
        code = tree.code(rel) or ""
        if not code.strip():
            continue
        raw = (base / rel).read_text(encoding="utf-8", errors="replace")
        spans = fn_spans(code)
        for rule, pat in RULES.items():
            for m in pat.finditer(code):
                fn = enclosing(spans, m.start())
                if rule == "founder" and re.search(r"\bconst\s+MEMBER_ROLE_FOUNDER\b",
                                                   code[max(0, m.start() - 20):m.end()]):
                    continue
                if rule == "bundle" and rel == "src/federation/edition2/genesis.rs":
                    continue
                if rule == "protocol":
                    # the argument: `..QUORUM_PREFIX`, or the literal
                    # `"quorum:` (literals are blanked in `code`; read the raw
                    # bytes at the same offset).
                    arg = raw[m.end():m.end() + 80].lstrip()
                    if not (arg.startswith('"quorum:') or re.match(r"[\w:]*QUORUM_PREFIX\b", arg)):
                        continue
                if rule == "present" and not DECISION_FN.search(fn):
                    continue
                add(rule, rel, fn)
                if rule == "walk" and (rel, fn) in MAY_ACT:
                    name = re.match(r"\w+", m.group(0)).group(0)
                    if name in TIMELESS_WALKERS:
                        hard.append(f"{rel}:{code.count(chr(10), 0, m.start()) + 1} ({fn}): a "
                                    f"room-duty act walks `{name}`, which reads edges timelessly; "
                                    f"call scoped_delegation_reach_in(.., act_at: Some(at)) (SD-fix1, CC 4.5.5)")
                    elif name == "scoped_delegation_reach_in":
                        args = call_args(code, m.end() - 1)
                        if not args or args[-1] == "None":
                            hard.append(f"{rel}:{code.count(chr(10), 0, m.start()) + 1} ({fn}): a "
                                        f"room-duty act walks with act_at None; pass the act's "
                                        f"instant (SD-fix1, CC 4.5.5)")
        for m in STRUCT_RE.finditer(code):
            end = efd.brace_pairs_cached(code).get(m.end() - 1)
            if end is None:
                continue
            fields = set(FIELD_RE.findall(code[m.end() - 1:end]))
            if fields & NEED_FIELDS and fields & OF_FIELDS:
                add("count-shape", rel, m.group(1))
    return found, hard


def check(base: Path, ratchet=None) -> list[str]:
    ratchet = RATCHET if ratchet is None else ratchet
    found, red = sites(base)
    for key, n in sorted(found.items()):
        if key not in ratchet:
            red.append(f"{key[1]} ({key[2]}): a NEW `{key[0]}` site ({n}); route it through the "
                       f"one reader, or (reviewed) add a RATCHET entry")
        elif n > ratchet[key][0]:
            red.append(f"{key[1]} ({key[2]}): `{key[0]}` grew from {ratchet[key][0]} to {n}")
    for key, (n, _) in sorted(ratchet.items()):
        have = found.get(key, 0)
        if have < n:
            red.append(f"{key[1]} ({key[2]}): `{key[0]}` shrank from {n} to {have}; lower "
                       f"(or delete) its RATCHET entry in the same change")
    return red


def listing(base: Path) -> str:
    found, _ = sites(base)
    lines = []
    for key, n in sorted(found.items()):
        why = RATCHET.get(key, (0, "TODO: why"))[1]
        lines.append(f"    ({key[0]!r}, {key[1]!r}, {key[2]!r}): ({n}, {why!r}),")
    return "\n".join(lines)


def self_test() -> int:
    lib = {"src/lib.rs": "pub mod federation;\n",
           "src/federation/mod.rs": "pub mod admission;\npub mod other;\n"}
    adm = ("pub const MEMBER_ROLE_FOUNDER: &str = \"founder\";\n"
           "pub async fn is_named_moderator(d: &D, k: &str, at: T) -> bool {\n"
           "    scoped_delegation_reach_in(d, k, &t, s, 5, P, Some(at), CommunityWalk::In(c), Some(at)).await\n}\n")
    r = lambda rule, fn, n=1, f="src/federation/admission.rs": {(rule, f, fn): (n, "fixture")}  # noqa: E731
    base_ratchet = r("walk", "is_named_moderator")
    cases = [
        ("the seam with act_at passes", {"src/federation/admission.rs": adm}, base_ratchet, 0),
        ("act_at None in a may-act fn is red (SD-fix1)",
         {"src/federation/admission.rs": adm.replace("Some(at))", "None)")}, base_ratchet, 1),
        ("a timeless wrapper in a may-act fn is red",
         {"src/federation/admission.rs": adm.replace("scoped_delegation_reach_in(", "scoped_delegation_reach(")},
         {("walk", "src/federation/admission.rs", "is_named_moderator"): (1, "x")}, 1),
        ("a new walk caller is red",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "fn g(d: &D) { issuer_reaches_target_via_scoped_delegation(d, a, b, c, 5, P, None); }\n"}, base_ratchet, 1),
        ("a grown site is red",
         {"src/federation/admission.rs": adm.replace(".await\n}", ".await;\n    scoped_delegation_reach_in(d, k, &t, s, 5, P, Some(at), w, Some(at)).await\n}")},
         base_ratchet, 1),
        ("a stale entry is red",
         {"src/federation/admission.rs": adm}, {**base_ratchet, **r("bundle", "gone")}, 1),
        ("a new founder-role comparison is red; the const is not a site",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "fn f(m: &M) -> bool { m.role.as_deref() == Some(MEMBER_ROLE_FOUNDER) }\n"}, base_ratchet, 1),
        ("a bundle-holders read outside genesis.rs is red",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "async fn f(d: &D) { let h = genesis_in_force(d).await?.holders(); }\n"}, base_ratchet, 1),
        ("a quorum: parser is red; another literal prefix is not",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "fn p(s: &str) { s.strip_prefix(\"quorum:\"); s.strip_prefix(\"open:\"); s.strip_prefix(cp::QUORUM_PREFIX); }\n"},
         base_ratchet, 1),
        ("a present read in a decision fn is red; in a display fn it is not",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "async fn check_x(d: &D) { effective_roster(d, c).await; }\nasync fn show(d: &D) { effective_roster(d, c).await; }\n"},
         base_ratchet, 1),
        ("a reserved-role label read is red",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "fn f(r: &R) -> bool { r.claims_role(identity_type::WISE_AUTHORITY) }\n"}, base_ratchet, 1),
        ("a have/need/of struct is red; a struct with only one of them is not",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "pub struct Tally { pub need: usize, pub roster_size: usize }\npub struct Other { pub need: usize }\n"},
         base_ratchet, 1),
        ("comments, literals and tests are not production",
         {"src/federation/admission.rs": adm, "src/federation/other.rs":
          "// MEMBER_ROLE_FOUNDER genesis_in_force(\nconst S: &str = \"x.holders()\";\n"
          "#[cfg(test)]\nmod t { fn f() { effective_roster(d, c); } }\n"}, base_ratchet, 0),
    ]
    bad = 0
    for name, files, ratchet, want in cases:
        with tempfile.TemporaryDirectory() as d:
            for rel, text in {**lib, "src/federation/other.rs": "\n", **files}.items():
                p = Path(d) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            reds = check(Path(d), ratchet)
            ok = len(reds) == want
            bad += not ok
            print(("ok  " if ok else "FAIL"), name, f"(reds {len(reds)}, want {want})")
            if not ok:
                for x in reds:
                    print("     ", x)
    print(f"self-test: {len(cases) - bad}/{len(cases)}")
    return 1 if bad else 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:] == ["list"]:
        print(listing(root()))
        return 0
    if sys.argv[1:] != ["check"]:
        print(__doc__)
        return 2
    red = check(root())
    for x in red:
        print("RED", x)
    print("GREEN" if not red else f"RED: {len(red)}")
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main())
