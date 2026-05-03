-- V007 — Edge outbound queue (sqlite, v0.4.0).
-- Postgres counterpart at migrations/postgres/lens/V007__edge_outbound_queue.sql.
--
-- SQLite differences:
--   - UUID is a string column (sqlite has no native UUID type)
--   - BYTEA → BLOB; TIMESTAMPTZ → TEXT (rfc3339)
--   - DEFAULT gen_random_uuid() not available; the application
--     generates the UUID at insert time
--   - No partial index WHERE clauses are needed — sqlite plans
--     well off the regular indexes here (and the dataset is
--     bounded by deployment size).

CREATE TABLE IF NOT EXISTS edge_outbound_queue (
    queue_id                   TEXT PRIMARY KEY,

    sender_key_id              TEXT NOT NULL,
    destination_key_id         TEXT NOT NULL,

    message_type               TEXT NOT NULL,
    edge_schema_version        TEXT NOT NULL,
    envelope_bytes             BLOB NOT NULL,
    body_sha256                BLOB NOT NULL,
    body_size_bytes            INTEGER NOT NULL,

    status                     TEXT NOT NULL,
    enqueued_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    next_attempt_after         TEXT NOT NULL,
    last_attempt_at            TEXT,
    transport_delivered_at     TEXT,
    delivered_at               TEXT,
    abandoned_at               TEXT,
    abandoned_reason           TEXT,

    attempt_count              INTEGER NOT NULL DEFAULT 0,
    max_attempts               INTEGER NOT NULL,
    ttl_seconds                INTEGER NOT NULL,
    last_error_class           TEXT,
    last_error_detail          TEXT,
    last_transport             TEXT,

    requires_ack               INTEGER NOT NULL,  -- bool: 0/1
    ack_timeout_seconds        INTEGER,
    ack_envelope_bytes         BLOB,
    ack_received_at            TEXT,

    claimed_until              TEXT,
    claimed_by                 TEXT,

    FOREIGN KEY (sender_key_id) REFERENCES federation_keys(key_id),
    FOREIGN KEY (destination_key_id) REFERENCES federation_keys(key_id),

    CHECK (status IN ('pending', 'sending', 'awaiting_ack', 'delivered', 'abandoned')),
    CHECK (abandoned_reason IS NULL OR abandoned_reason IN ('max_attempts', 'ttl_expired', 'operator_cancel')),
    CHECK (body_size_bytes BETWEEN 1 AND 8388608),
    CHECK (length(body_sha256) = 32),
    CHECK (max_attempts > 0),
    CHECK (ttl_seconds > 0),
    CHECK ((NOT requires_ack) OR (ack_timeout_seconds IS NOT NULL AND ack_timeout_seconds > 0)),
    CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK ((status = 'abandoned') = (abandoned_at IS NOT NULL AND abandoned_reason IS NOT NULL)),
    CHECK ((ack_envelope_bytes IS NOT NULL) = (ack_received_at IS NOT NULL)),
    CHECK (ack_received_at IS NULL OR requires_ack = 1)
);

CREATE INDEX IF NOT EXISTS edge_outbound_queue_pending_dispatch
    ON edge_outbound_queue (next_attempt_after)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS edge_outbound_queue_awaiting_ack_sweep
    ON edge_outbound_queue (transport_delivered_at)
    WHERE status = 'awaiting_ack';

CREATE INDEX IF NOT EXISTS edge_outbound_queue_body_sha256_awaiting
    ON edge_outbound_queue (body_sha256)
    WHERE status = 'awaiting_ack';

CREATE INDEX IF NOT EXISTS edge_outbound_queue_destination
    ON edge_outbound_queue (destination_key_id, status);

CREATE INDEX IF NOT EXISTS edge_outbound_queue_status_enqueued
    ON edge_outbound_queue (status, enqueued_at);

CREATE INDEX IF NOT EXISTS edge_outbound_queue_claimed_until_sweep
    ON edge_outbound_queue (claimed_until)
    WHERE status = 'sending';
