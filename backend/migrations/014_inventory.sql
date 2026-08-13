-- Migration 014: Create inventory table for DSPM asset inventory

CREATE TABLE IF NOT EXISTS inventory_assets (
    id UUID PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_hash_sha256 TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    last_accessed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    first_scanned_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_inventory_file_hash ON inventory_assets (file_hash_sha256);
CREATE INDEX IF NOT EXISTS idx_inventory_owner ON inventory_assets (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_inventory_path ON inventory_assets (file_path);
