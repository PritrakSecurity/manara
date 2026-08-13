-- Migration 003: Add AD Configuration and Sync Jobs Tables
-- Created: 2026-01-06
-- Purpose: Store AD credentials and sync job progress

-- AD Configuration table
CREATE TABLE IF NOT EXISTS ad_configuration (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server VARCHAR(255) NOT NULL,
  port INTEGER NOT NULL DEFAULT 389,
  username VARCHAR(255) NOT NULL,
  password_encrypted VARCHAR(1000) NOT NULL,
  base_dn VARCHAR(500),
  test_result_status VARCHAR(50) DEFAULT 'untested', -- 'success', 'failure', 'untested'
  test_result_message TEXT,
  last_tested_at TIMESTAMPTZ,
  last_synced_at TIMESTAMPTZ,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  created_by VARCHAR(255),
  updated_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_ad_config_active ON ad_configuration(is_active);

-- Sync Jobs table
CREATE TABLE IF NOT EXISTS sync_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  status VARCHAR(50) NOT NULL DEFAULT 'starting', -- 'starting', 'syncing', 'completed', 'failed'
  progress INTEGER NOT NULL DEFAULT 0,
  found INTEGER NOT NULL DEFAULT 0,
  added INTEGER NOT NULL DEFAULT 0,
  updated INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sync_jobs_status ON sync_jobs(status);
CREATE INDEX IF NOT EXISTS idx_sync_jobs_created_at ON sync_jobs(created_at DESC);

-- Devices table (if not exists, add columns for AD sync)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'devices' AND column_name = 'hostname') THEN
    CREATE TABLE IF NOT EXISTS devices (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      hostname VARCHAR(255) NOT NULL,
      ip_address VARCHAR(45),
      os_version VARCHAR(255),
      status VARCHAR(50) DEFAULT 'online',
      last_seen TIMESTAMPTZ DEFAULT NOW(),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
