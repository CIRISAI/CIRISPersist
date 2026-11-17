# Verify release/23.2.0 — genesis bundle/2 reader (ciris_verify_core::edition2::genesis, std tier)
read_genesis_bundles(&GenesisInput) -> GenesisReading { bundles: Vec<BundleReading>, refused: Vec<RefusedStatement> }
verify_genesis_bundle(&Digest32 object_id, &GenesisInput) -> Option<BundleReading>
find_forks(&[&GenesisPlacement]) -> Vec<Fork>   // Fork::{Genesis{bundles}, Successors{prev, bundles}}
follow_to_head(&[&GenesisPlacement]) -> Head     // Head::{Head(&p), Fork(Vec<Fork>), Nothing}
identity_ref_thumbprint(&str) -> Option<Digest32>
GenesisInput { statements: &[Vec<u8>], rows: &BTreeMap<Digest32, Vec<u8>> (row statements by row id),
  anchor: Option<&Anchor> (Thumbprints(BTreeSet<Digest32>) | ObjectId(Digest32)),
  predecessors: &[Predecessor] (Valid(&GenesisPlacement) | NotValid(Digest32)),
  attestation_roots: &TrustAnchorStore (prod: trust_anchor_store::baked::default_store()) }
BundleReading { object_id, verdict: GenesisVerdict, refused }
GenesisVerdict = Valid(Box<GenesisPlacement>) | Invalid(Malformed) | Waiting(GenesisWaiting{rows, prev, kids}) | Nothing(Inconclusive)
GenesisPlacement: object_id, version, prev, asserted_at, family_key_id, holders[], seats[], witnesses, charter (halt_fuse()), counted, is_canonical(iref)
  holder: identity-ref, kid, composite key, recovery commitment, hardware_class, pq_custody, record row id
  seat: identity-ref, kid, key, valid_until, transit_xwing_pubkey + onion_hop_xwing_pubkey (1216 B each), record + binding row ids
Malformed::reason(): version_prev_mismatch, holders_seats_overlap, recovery_commitments_not_holders, scope_missing_infra, witness_members_partial, witness_quorum_mismatch, federation_set_semantics_unsorted, genesis_bundle_schema, family_key_id_changed
Inconclusive::token(): genesis_bundle_not_anchored, _prev_not_valid, _row_unplaced, _row_invalid (RowFault), genesis_holder_custody (CustodyFault), _count_unmet
edition2::recovery::{recovery_commitment, recovery_commitment_input, checked_recovery_commitment}
KeyRecord gains hardware_class + chain (bad chain → key_record_bad_attestation_evidence)
Vectors: tests/vectors/edition2/genesis/ (70 cases; statements split across pool_0..3)
Open with CC: per-statement iat refuses one statement, not the bundle; X-Wing keys at the binding payload's TOP LEVEL beside transport_destination.
