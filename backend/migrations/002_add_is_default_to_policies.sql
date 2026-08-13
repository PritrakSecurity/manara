-- Add is_default column to policies table
ALTER TABLE policies ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_policies_is_default ON policies(is_default);
