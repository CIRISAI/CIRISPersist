-- V034 — wa_cert substrate (v1.5.19, CIRISPersist#59 #11).
--
-- ELEVENTH and FINAL substrate absorption ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Absorbs the agent's
-- `wa_cert` table — the Wise-Authority cert directory. Per the
-- "persist is the only library that opens the file" guarantee these
-- WA certs live in the engine DB (NOT a separate auth.db) so the
-- pyo3 surface speaks to one Engine and one DSN regardless of
-- backend.
--
-- # Agent's 24-column shape (CIRISAgent v2.8.13)
--
--   wa_id                  TEXT PRIMARY KEY
--   name                   TEXT NOT NULL
--   role                   TEXT CHECK(role IN ('root','authority','observer'))
--   pubkey                 TEXT NOT NULL
--   jwt_kid                TEXT NOT NULL UNIQUE
--   password_hash          TEXT
--   api_key_hash           TEXT
--   oauth_provider         TEXT
--   oauth_external_id      TEXT
--   oauth_links_json       TEXT
--   veilid_id              TEXT
--   auto_minted            INTEGER DEFAULT 0
--   parent_wa_id           TEXT  (self-FK → wa_cert.wa_id)
--   parent_signature       TEXT
--   scopes_json            TEXT NOT NULL
--   custom_permissions_json TEXT
--   adapter_id             TEXT
--   adapter_name           TEXT
--   adapter_metadata_json  TEXT
--   token_type             TEXT DEFAULT 'standard'
--   created                TEXT NOT NULL
--   last_login             TEXT
--   active                 INTEGER DEFAULT 1
--
-- PG dialect:
--   * `_json` suffixed TEXT columns → JSONB columns sans the suffix
--     (`oauth_links`, `scopes`, `custom_permissions`,
--     `adapter_metadata`).
--   * `INTEGER DEFAULT 0/1` → `BOOLEAN NOT NULL DEFAULT FALSE/TRUE`.
--   * `created` / `last_login` → `TIMESTAMPTZ`.
--   * `role` retains the CHECK with NOT NULL added (the agent's PK
--     pattern keeps role non-null in practice; we make it explicit).
--   * `token_type` adds a CHECK over the inferred 5-value vocabulary
--     (`standard | session | api_key | oauth | service`). Inferred
--     from the agent's TokenType enum; caller-validated either way
--     since cert mint happens in CIRISAgent.
--   * Self-FK on `parent_wa_id` is DEFERRABLE INITIALLY DEFERRED so a
--     one-tx ceremony writing a parent + child WA pair in either order
--     is supported.
--
-- Indexes mirror the agent's hot paths: JWT verify (kid), OAuth login
-- (provider + external_id), role-based listing (list_observers /
-- list_authorities), per-adapter cert enumeration, parent-child tree
-- walks.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.wa_cert (
    wa_id                  TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    role                   TEXT NOT NULL
        CHECK (role IN ('root','authority','observer')),
    pubkey                 TEXT NOT NULL,
    jwt_kid                TEXT NOT NULL UNIQUE,
    password_hash          TEXT,
    api_key_hash           TEXT,
    oauth_provider         TEXT,
    oauth_external_id      TEXT,
    oauth_links            JSONB,
    veilid_id              TEXT,
    auto_minted            BOOLEAN NOT NULL DEFAULT FALSE,
    parent_wa_id           TEXT,
    parent_signature       TEXT,
    scopes                 JSONB NOT NULL,
    custom_permissions     JSONB,
    adapter_id             TEXT,
    adapter_name           TEXT,
    adapter_metadata       JSONB,
    token_type             TEXT NOT NULL DEFAULT 'standard'
        CHECK (token_type IN ('standard','session','api_key','oauth','service')),
    created                TIMESTAMPTZ NOT NULL,
    last_login             TIMESTAMPTZ,
    active                 BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT wa_cert_parent_fk
        FOREIGN KEY (parent_wa_id) REFERENCES cirislens.wa_cert(wa_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Lookup-by-kid is the JWT verification hot path.
CREATE UNIQUE INDEX wa_cert_jwt_kid ON cirislens.wa_cert (jwt_kid);
-- OAuth login path.
CREATE INDEX wa_cert_oauth ON cirislens.wa_cert (oauth_provider, oauth_external_id)
    WHERE oauth_provider IS NOT NULL AND oauth_external_id IS NOT NULL;
-- Role-based listing (e.g. list_observers, list_authorities).
CREATE INDEX wa_cert_role_active ON cirislens.wa_cert (role, active)
    WHERE active = TRUE;
-- Adapter-bound certs (per-adapter WA enumeration).
CREATE INDEX wa_cert_adapter ON cirislens.wa_cert (adapter_id)
    WHERE adapter_id IS NOT NULL;
-- Parent-child tree walks.
CREATE INDEX wa_cert_parent ON cirislens.wa_cert (parent_wa_id)
    WHERE parent_wa_id IS NOT NULL;

COMMENT ON TABLE cirislens.wa_cert IS
    'v1.5.19 (CIRISPersist#59 #11, FINAL) — wa_cert substrate. Absorbs CIRISAgent ciris_engine.db.wa_cert; the Wise-Authority cert directory keyed on wa_id. 24 columns matching the agent (TEXT JSON columns promoted to JSONB; INTEGER 0/1 booleans promoted to BOOLEAN; TEXT timestamps promoted to TIMESTAMPTZ). Lives in the engine DB (not a separate auth.db) per the persist-is-the-only-library-opening-the-file guarantee. Self-FK on parent_wa_id is DEFERRABLE INITIALLY DEFERRED so a one-tx ceremony writing parent + child in either order is supported. JWT-verify hot path hits the unique jwt_kid index; OAuth login hits the partial oauth index; list_observers / list_authorities hits the role+active partial index.';
