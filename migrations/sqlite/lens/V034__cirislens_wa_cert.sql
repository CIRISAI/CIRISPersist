-- V034 — wa_cert substrate (v1.5.19, CIRISPersist#59 #11).
--
-- SQLite mirror of V034 PG. Dialect translations:
--   TIMESTAMPTZ                          → TEXT (RFC 3339)
--   JSONB                                → TEXT (raw JSON string)
--   BOOLEAN                              → INTEGER (0 / 1)
--   DEFERRABLE INITIALLY DEFERRED        → omitted (SQLite has only
--                                          immediate-mode FK
--                                          enforcement with
--                                          PRAGMA foreign_keys=ON)
--
-- 24 columns matching the agent's source schema. Self-FK on
-- parent_wa_id only fires when the value is non-NULL — SQLite handles
-- nullable FKs natively (NULL passes the constraint check without
-- lookup).
--
-- The store layer always sets PRAGMA foreign_keys = ON so the FK is
-- enforced at insert time; non-NULL parent_wa_id MUST reference an
-- existing cirislens_wa_cert row.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens_wa_cert (
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
    oauth_links            TEXT,
    veilid_id              TEXT,
    auto_minted            INTEGER NOT NULL DEFAULT 0,
    parent_wa_id           TEXT,
    parent_signature       TEXT,
    scopes                 TEXT NOT NULL,
    custom_permissions     TEXT,
    adapter_id             TEXT,
    adapter_name           TEXT,
    adapter_metadata       TEXT,
    token_type             TEXT NOT NULL DEFAULT 'standard'
        CHECK (token_type IN ('standard','session','api_key','oauth','service')),
    created                TEXT NOT NULL,
    last_login             TEXT,
    active                 INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (parent_wa_id) REFERENCES cirislens_wa_cert(wa_id)
);

CREATE UNIQUE INDEX wa_cert_jwt_kid ON cirislens_wa_cert (jwt_kid);
CREATE INDEX wa_cert_oauth ON cirislens_wa_cert (oauth_provider, oauth_external_id)
    WHERE oauth_provider IS NOT NULL AND oauth_external_id IS NOT NULL;
CREATE INDEX wa_cert_role_active ON cirislens_wa_cert (role, active) WHERE active = 1;
CREATE INDEX wa_cert_adapter ON cirislens_wa_cert (adapter_id) WHERE adapter_id IS NOT NULL;
CREATE INDEX wa_cert_parent ON cirislens_wa_cert (parent_wa_id) WHERE parent_wa_id IS NOT NULL;
