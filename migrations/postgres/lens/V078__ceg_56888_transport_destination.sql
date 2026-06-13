-- V078 — CEG §5.6.8.8.1 transport_destination: per-occurrence reachability
--        rows for the "self at login" substrate (CIRISPersist#183,
--        CEG §8.1.12.7). Postgres dialect. SQLite parity: sqlite/lens/V078.
--
-- §5.6.8.7.7 / §5.6.8.8.1: an identity_occurrence (a person's phone, laptop,
-- or agent — bound via V069 federation_identity_occurrences, #153) needs a
-- way for peers to *reach* it on the network. A transport_destination row
-- records one reachable address for one occurrence: the transport kind
-- ("reticulum" / "websocket" / "https" / operator-defined) and the address
-- string (a Reticulum destination hash, a wss:// URL, etc.). An occurrence
-- MAY register several (a phone reachable over both Reticulum and a relay
-- websocket), so the PK is composite over (occurrence_key_id, transport_kind,
-- destination) and writes are idempotent on it.
--
-- This is the §8.1.12.7 "show up on the network" substrate half: after the
-- federation-tier delegation promotion makes the agent occurrence's
-- authority verifiable, the transport rows tell peers WHERE to send to it.
-- Reachability is mutable and disposable — a stale relay address is dropped
-- and re-registered, not revoked — so there is no signature / persist_row_hash
-- on these rows (unlike the V069 occurrence binding they hang off). The FK to
-- federation_keys(key_id) keeps an address from naming an occurrence key the
-- directory has never seen.
--
-- last_seen_at is advisory liveness (operators sweep stale destinations); it
-- is NOT a lease — occurrence liveness is the V069 binding's valid_until plus
-- the separate occurrence-registration TTL (src/occurrence/). Refinery wraps
-- this migration in its own transaction.

CREATE TABLE IF NOT EXISTS cirislens.transport_destinations (
    occurrence_key_id    TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    -- Open vocab: 'reticulum' / 'websocket' / 'https' / operator-defined.
    transport_kind       TEXT NOT NULL,
    -- The reachable address (Reticulum destination hash, wss:// URL, …).
    destination          TEXT NOT NULL,
    -- When the address was (re)asserted; RFC-3339 UTC via TIMESTAMPTZ.
    asserted_at          TIMESTAMPTZ NOT NULL,
    -- Advisory liveness — operators sweep stale destinations. NOT a lease.
    last_seen_at         TIMESTAMPTZ,
    PRIMARY KEY (occurrence_key_id, transport_kind, destination)
);

-- Reachability lookup: "how do I reach this occurrence?" seeks by occurrence.
CREATE INDEX IF NOT EXISTS transport_destinations_by_occurrence
    ON cirislens.transport_destinations (occurrence_key_id);
