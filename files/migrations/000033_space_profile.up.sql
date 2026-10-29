-- The name and image the owner shows every account on this space (#309). One row.
CREATE TABLE space_profile (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    name TEXT NOT NULL DEFAULT '',
    avatar_storage_id TEXT,
    updated_at BIGINT NOT NULL DEFAULT 0
);
