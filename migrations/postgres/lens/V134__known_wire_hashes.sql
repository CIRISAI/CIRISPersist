-- V134: the KNOWN-but-not-held wire-hash set (CIRISPersist#785).
-- Postgres dialect. SQLite twin: migrations/sqlite/lens/V134.
--
-- ─── What this answers, and what it must never answer ───────────────
--
-- `signed_wire_index` (V111) answers "WHAT DO I HOLD". Every entry there
-- carries a NOT NULL `record_key` pointing at the row, which is exactly
-- right for the #780 point-read and the holdings half of
-- `want = remote ∖ holdings`.
--
-- This table answers a DIFFERENT question: "WHAT EXISTS IN THE
-- FEDERATION", for records whose bodies this node deliberately does not
-- hold. Under the hash-first directory (CIRISEdge#552) a node converges
-- the hash set at federation tier and fetches a body only on demand, so
-- most known hashes will never have a row and can never appear in the
-- wire index.
--
-- ─── Why a SEPARATE TABLE and not a flag on signed_wire_index ────────
--
-- These two sets MUST NEVER be unioned into the holdings read. If a
-- known-but-not-held hash reaches `holdings`, the node concludes it
-- already has everything it has merely HEARD OF and silently stops
-- fetching: nothing errors, anti-entropy goes quiet, and the corpus
-- freezes at whatever it had (CIRISEdge#416's non-convergence with the
-- sign flipped).
--
-- Today that union is UNREPRESENTABLE, and it is the schema that makes
-- it so: `signed_wire_index.record_key` is NOT NULL, so a hash with no
-- row cannot be inserted there at all. Adding these as a flag on that
-- table would require making `record_key` NULLABLE — spending the one
-- constraint that makes the mistake impossible, in a migration that
-- reads like housekeeping. Hence a distinct table with NO `record_key`
-- column: not as a convention, but so that pointing one of these rows
-- at a held record is not a thing that can be spelled.
--
-- Note also that the read path cannot warn you. #780's
-- `lookup_signed_record_by_content_hash` returns `Ok(None)` on a stale
-- or mismatched entry by design (self-healing posture) — so a polluted
-- holdings read raises nothing on either side. "We would notice" is not
-- available as a mitigation here.
--
-- ─── Columns ────────────────────────────────────────────────────────
--
-- `kind`               — the `EnvelopeKind::as_str()` token, same
--                        vocabulary as `signed_wire_index.kind`.
-- `content_hash`       — lowercase-hex sha256, the same value the
--                        advertising peer computed; identical
--                        derivation to the wire index, so a hash can be
--                        compared across the two sets even though the
--                        ROWS may never be joined.
-- `last_advertised_at` — the moment a peer most recently advertised
--                        this hash. THIS COLUMN MUST MOVE. Edge's
--                        advertise axis is a watermark sweep with a
--                        rolling re-sweep that WRAPS, so every live
--                        hash is re-advertised once per wrap period,
--                        forever. Ageing on a first-seen column instead
--                        would reproduce #776 exactly: that prune aged
--                        on `asserted_at`, a value the writer freezes,
--                        so the cutoff never advanced, the prune never
--                        fired, and both consumers independently
--                        refused to call it rather than reporting a
--                        fault. The column that moves is the one the
--                        re-sweep touches.
-- `advertised_by`      — LOCAL-ONLY. The peer that advertised this hash
--                        to this node. See the replication note below.
--
-- ─── advertised_by is an OBSERVATION, never a CLAIM, and never leaves ─
--
-- It records "this peer advertised H to me", NOT "this peer holds H".
-- It is deliberately absent from every replication policy kind and from
-- the wire index, and no type carrying it reaches an envelope. A
-- replicated version would be a who-holds-what index over the ENTIRE
-- corpus — a strictly larger disclosure than the one CIRISPersist#784
-- is trying to keep out of moderation records for a handful of
-- moderated subjects. Staying local adds no disclosure at all, since it
-- is derived from Summaries that peer already sent us: the information
-- is ours either way, and what matters is that it never becomes anyone
-- else's.
--
-- No BEGIN/COMMIT: refinery wraps each migration in its own transaction
-- (V019 rule).

CREATE TABLE IF NOT EXISTS cirislens.known_wire_hashes (
    kind                TEXT NOT NULL,
    content_hash        TEXT NOT NULL,
    last_advertised_at  TIMESTAMPTZ NOT NULL,
    advertised_by       TEXT,
    PRIMARY KEY (kind, content_hash)
);

-- The eviction sweep orders on the column that moves. Kind-leading so a
-- per-kind bound can be enforced without scanning the whole set.
CREATE INDEX IF NOT EXISTS known_wire_hashes_age
    ON cirislens.known_wire_hashes (kind, last_advertised_at);
