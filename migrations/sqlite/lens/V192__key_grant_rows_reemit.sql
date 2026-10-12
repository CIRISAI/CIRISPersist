-- V192 — the key-grant SET is retired; every emission axis goes dirty so a
-- node re-emits the wraps it holds as per-recipient rows. SQLite dialect.
-- v55.0.0 (CIRISPersist#989, CC 3.3.2 rc7, CIRISConstitution#143).
--
-- POSTGRES PARITY: migrations/postgres/lens/V192__key_grant_rows_reemit.sql
--
-- WHY
-- ---
-- Through v54 a node carried the wraps of one key as one SET row
-- (`attestation_type = key_grant:{axis}:v1`). CC rc7 retires the carrier
-- class: a wrap is one `scores` row per recipient on `key_grant:{axis}:v1`.
-- The operator's ruling (Q3, 2026-10-09): keep the local wraps; on first boot
-- each node re-emits its OWN legacy sets as per-recipient rows; held sets are
-- no longer served; new set writes are refused.
--
-- The local grant tables already hold every wrap a set carried, and the
-- V146 emission ledger already drives emission: an axis whose
-- `key_grant_emitted_at` is NULL is dirty, and the boot sweep
-- (`Engine::emit_pending_key_grants`, PyO3 `__init__`) emits every dirty axis
-- the node owns as minter or sealer. So the re-emit is this one reset, and the
-- sweep does the rest under the v55 emitter: each row at a fresh signed
-- instant, each recipient re-checked against the audience rule at that
-- instant (CC 4.4.3.2.2: a party removed since is not re-wrapped), only the
-- wraps the node can still sign as sealer or minter. The emitter skips a wrap
-- already held as a row, so a second pass, or a re-run of this reset, emits
-- nothing new.
--
-- The pending index (V146) holds content-axis SETS that arrived before their
-- bytes. A set is never projected again; the sealer's own re-emission
-- delivers the rows, so the stale index entries are dropped here.
--
-- Data only: no DDL. The retired set rows themselves stay where they are;
-- the serve reads leave them out (`row_type::RETIRED_ROW_TYPE_PREFIXES`).
UPDATE federation_community_dek SET key_grant_emitted_at = NULL
 WHERE key_grant_emitted_at IS NOT NULL;
UPDATE federation_blobs SET key_grant_emitted_at = NULL
 WHERE key_grant_emitted_at IS NOT NULL;
UPDATE federation_stream_deks SET key_grant_emitted_at = NULL
 WHERE key_grant_emitted_at IS NOT NULL;
DELETE FROM federation_key_grant_pending;
