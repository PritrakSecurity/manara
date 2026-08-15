-- Migration 015: DSPM upgrade - contextual risk scoring, exposure levels, and data snippets

ALTER TABLE inventory_assets ADD COLUMN IF NOT EXISTS exposure_level VARCHAR(50) DEFAULT 'INTERNAL';
ALTER TABLE inventory_assets ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE inventory_assets ADD COLUMN IF NOT EXISTS content_snippet TEXT;
ALTER TABLE inventory_assets ADD COLUMN IF NOT EXISTS owner_sid VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_inventory_risk ON inventory_assets (risk_score);
CREATE INDEX IF NOT EXISTS idx_inventory_exposure ON inventory_assets (exposure_level);
