-- V157 — the delegation depth a `withdraws` was admitted under
-- v50.0.0 (CIRISPersist#928, review H2 final check)
--
-- SQLITE PARITY: migrations/sqlite/lens/V157__withdraws_admission_depth.sql
--
-- # Why
--
-- CC 4.1.1 caps a delegation walk at 5 hops by default; persist's write gate
-- for `withdraws` took that default in v50.0.0 (it walked 16 before). The
-- bytes-plane fold re-derives every stored `withdraws` at READ time
-- (CIRISPersist#853: re-derive, never read the stored rule), so it has to know
-- the depth the row was admitted under. Re-walking at the new default would
-- un-retire bytes a pre-v50 withdraws validly retired; re-walking at the old
-- ceiling would let a NEW withdraws admitted by the deferred arm (target
-- absent at admission) retire bytes through a 6-16 hop chain the gate now
-- refuses. So the depth is recorded per row.
--
-- # What changes
--
-- `federation_withdraws_admission_depths` — one row per admitted `withdraws`:
-- the walk depth its admission used (5 by default, or the host's explicit
-- opt-in up to the 16 ceiling). Every `withdraws` stored before this migration
-- was admitted under the 16-hop walk and is backfilled with 16. A row with no
-- entry reads as 16. No foreign key, as on sqlite.

CREATE TABLE IF NOT EXISTS cirislens.federation_withdraws_admission_depths (
    attestation_id TEXT PRIMARY KEY,
    depth          INTEGER NOT NULL CHECK (depth BETWEEN 0 AND 16)
);

INSERT INTO cirislens.federation_withdraws_admission_depths (attestation_id, depth)
SELECT attestation_id, 16 FROM cirislens.federation_attestations
 WHERE attestation_type = 'withdraws'
ON CONFLICT (attestation_id) DO NOTHING;
