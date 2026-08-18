-- Migration 017: Store privacy-safe classification findings on assets/events.

ALTER TABLE event_logs ADD COLUMN IF NOT EXISTS findings JSONB;
ALTER TABLE inventory_assets ADD COLUMN IF NOT EXISTS findings JSONB;
