-- Migration 016: Fix schema drift
-- Reconciles the `users` and `ad_users` tables with the Go code.
--
--   * `users` is missing first_name / last_name / is_active / is_ad_synced /
--     last_ad_sync because migration 001 already created the table and
--     migration 006's `CREATE TABLE IF NOT EXISTS users` (which defines those
--     columns) is a no-op. handleLogin and the AD user handlers query these
--     columns, so every login / AD-sync operation fails on a fresh install.
--   * `ad_users` is referenced by CreateUserFromAD and ListADUsers but no
--     migration creates it, so those endpoints 500 at runtime.

-- Add first_name to users if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='users' AND column_name='first_name') THEN
        ALTER TABLE users ADD COLUMN first_name VARCHAR(255);
    END IF;
END $$;

-- Add last_name to users if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='users' AND column_name='last_name') THEN
        ALTER TABLE users ADD COLUMN last_name VARCHAR(255);
    END IF;
END $$;

-- Add is_active to users if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='users' AND column_name='is_active') THEN
        ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE;
    END IF;
END $$;

-- Add is_ad_synced to users if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='users' AND column_name='is_ad_synced') THEN
        ALTER TABLE users ADD COLUMN is_ad_synced BOOLEAN DEFAULT FALSE;
    END IF;
END $$;

-- Add last_ad_sync to users if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='users' AND column_name='last_ad_sync') THEN
        ALTER TABLE users ADD COLUMN last_ad_sync TIMESTAMP;
    END IF;
END $$;

-- Create ad_users table if it doesn't exist
CREATE TABLE IF NOT EXISTS ad_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    distinguished_name VARCHAR(500) UNIQUE NOT NULL,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    display_name VARCHAR(255),
    department VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    last_sync_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ad_users_distinguished_name ON ad_users(distinguished_name);
CREATE INDEX IF NOT EXISTS idx_ad_users_username ON ad_users(username);
