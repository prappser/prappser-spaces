-- Intentionally drops push_vapid_keys (per-user VAPID rows) as part of the migration to a single per-space keypair.
DROP TABLE IF EXISTS push_vapid_keys;

CREATE TABLE space_vapid (
    id                SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    vapid_public_key  TEXT NOT NULL,
    vapid_private_key TEXT NOT NULL,
    created_at        BIGINT NOT NULL,
    updated_at        BIGINT NOT NULL
);
