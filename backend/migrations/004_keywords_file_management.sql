-- Migration 004: Keywords and File Management Tables
-- Created: 2026-01-07
-- Purpose: Support content inspection, keyword detection, file classification

-- ============================================
-- KEYWORDS TABLE
-- For content inspection and classification
-- ============================================
CREATE TABLE IF NOT EXISTS keywords (
    id VARCHAR(50) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    keyword TEXT NOT NULL,
    match_type VARCHAR(20) NOT NULL DEFAULT 'PARTIAL', -- EXACT|PARTIAL|REGEX
    case_sensitive BOOLEAN DEFAULT FALSE,
    classification VARCHAR(50) NOT NULL DEFAULT 'PRIVATE', -- PUBLIC|PRIVATE|CONFIDENTIAL|RESTRICTED
    priority INT NOT NULL DEFAULT 50,
    hard_block BOOLEAN DEFAULT FALSE,
    description TEXT,
    tags TEXT[] DEFAULT '{}',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),

    CONSTRAINT keywords_match_type_check CHECK (match_type IN ('EXACT', 'PARTIAL', 'REGEX')),
    CONSTRAINT keywords_classification_check CHECK (classification IN ('PUBLIC', 'PRIVATE', 'CONFIDENTIAL', 'RESTRICTED')),
    CONSTRAINT keywords_priority_check CHECK (priority >= 0 AND priority <= 100)
);

-- Indexes for keywords
CREATE INDEX IF NOT EXISTS idx_keywords_classification ON keywords(classification);
CREATE INDEX IF NOT EXISTS idx_keywords_hard_block ON keywords(hard_block);
CREATE INDEX IF NOT EXISTS idx_keywords_enabled ON keywords(enabled);
CREATE INDEX IF NOT EXISTS idx_keywords_priority ON keywords(priority DESC);

-- ============================================
-- FILE OWNERSHIP TABLE
-- Track original file owners for authorization
-- ============================================
CREATE TABLE IF NOT EXISTS file_ownership (
    file_hash VARCHAR(64) PRIMARY KEY,
    original_owner_sid VARCHAR(255) NOT NULL,
    original_owner_username VARCHAR(255) NOT NULL,
    creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_type VARCHAR(50) DEFAULT 'LOCAL', -- LOCAL|DOWNLOAD|EMAIL|SHARE|CLOUD
    source_detail TEXT,
    last_verified TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT file_ownership_source_type_check CHECK (source_type IN ('LOCAL', 'DOWNLOAD', 'EMAIL', 'SHARE', 'CLOUD'))
);

-- Indexes for file ownership
CREATE INDEX IF NOT EXISTS idx_file_ownership_owner_sid ON file_ownership(original_owner_sid);
CREATE INDEX IF NOT EXISTS idx_file_ownership_owner_username ON file_ownership(original_owner_username);
CREATE INDEX IF NOT EXISTS idx_file_ownership_source_type ON file_ownership(source_type);

-- ============================================
-- CLASSIFIED FILES TABLE
-- Registry of files with assigned classifications
-- ============================================
CREATE TABLE IF NOT EXISTS classified_files (
    file_hash VARCHAR(64) PRIMARY KEY,
    file_name VARCHAR(500),
    file_path TEXT,
    classification VARCHAR(50) NOT NULL DEFAULT 'PRIVATE',
    classification_reason TEXT,
    matched_keywords TEXT[] DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed TIMESTAMPTZ DEFAULT NOW(),
    access_count INT DEFAULT 1,
    file_size BIGINT,
    file_type VARCHAR(50),
    mime_type VARCHAR(100),
    owner_sid VARCHAR(255),
    owner_username VARCHAR(255),
    quarantined BOOLEAN DEFAULT FALSE,
    quarantined_at TIMESTAMPTZ,
    quarantined_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT classified_files_classification_check CHECK (classification IN ('PUBLIC', 'PRIVATE', 'CONFIDENTIAL', 'RESTRICTED'))
);

-- Indexes for classified files
CREATE INDEX IF NOT EXISTS idx_classified_files_classification ON classified_files(classification);
CREATE INDEX IF NOT EXISTS idx_classified_files_owner_sid ON classified_files(owner_sid);
CREATE INDEX IF NOT EXISTS idx_classified_files_quarantined ON classified_files(quarantined);
CREATE INDEX IF NOT EXISTS idx_classified_files_first_seen ON classified_files(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_classified_files_file_type ON classified_files(file_type);

-- ============================================
-- FILE ACCESS HISTORY TABLE
-- Track who accessed what files
-- ============================================
CREATE TABLE IF NOT EXISTS file_access_history (
    id BIGSERIAL PRIMARY KEY,
    file_hash VARCHAR(64) NOT NULL,
    user_sid VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    device_id VARCHAR(100),
    hostname VARCHAR(255),
    action_type VARCHAR(50) NOT NULL, -- VIEW|COPY|MOVE|UPLOAD|DOWNLOAD|PRINT|EMAIL
    destination_type VARCHAR(50),
    destination_detail TEXT,
    decision VARCHAR(20) NOT NULL, -- ALLOW|BLOCK|PENDING
    policy_id UUID,
    rule_id VARCHAR(50),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT file_access_action_check CHECK (action_type IN ('VIEW', 'COPY', 'MOVE', 'UPLOAD', 'DOWNLOAD', 'PRINT', 'EMAIL', 'USB_TRANSFER', 'CLOUD_SYNC')),
    CONSTRAINT file_access_decision_check CHECK (decision IN ('ALLOW', 'BLOCK', 'PENDING'))
);

-- Indexes for file access history
CREATE INDEX IF NOT EXISTS idx_file_access_file_hash ON file_access_history(file_hash);
CREATE INDEX IF NOT EXISTS idx_file_access_user_sid ON file_access_history(user_sid);
CREATE INDEX IF NOT EXISTS idx_file_access_timestamp ON file_access_history(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_file_access_decision ON file_access_history(decision);

-- ============================================
-- KEYWORD GROUPS TABLE
-- Organize keywords into logical groups
-- ============================================
CREATE TABLE IF NOT EXISTS keyword_groups (
    id VARCHAR(50) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    default_classification VARCHAR(50) DEFAULT 'PRIVATE',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add group reference to keywords
ALTER TABLE keywords ADD COLUMN IF NOT EXISTS group_id VARCHAR(50) REFERENCES keyword_groups(id) ON DELETE SET NULL;

-- ============================================
-- INSERT DEFAULT KEYWORD GROUPS
-- ============================================
INSERT INTO keyword_groups (id, name, description, default_classification) VALUES
    ('grp-pii', 'Personal Identifiable Information', 'SSN, passport numbers, driver license', 'CONFIDENTIAL'),
    ('grp-financial', 'Financial Data', 'Credit cards, bank accounts, financial reports', 'CONFIDENTIAL'),
    ('grp-internal', 'Internal Codes', 'Company internal control codes and identifiers', 'RESTRICTED'),
    ('grp-healthcare', 'Healthcare/PHI', 'Protected health information, medical records', 'RESTRICTED'),
    ('grp-legal', 'Legal & Compliance', 'Legal documents, contracts, compliance data', 'CONFIDENTIAL')
ON CONFLICT DO NOTHING;

-- ============================================
-- INSERT DEFAULT KEYWORDS
-- ============================================
INSERT INTO keywords (id, keyword, match_type, case_sensitive, classification, priority, hard_block, description, group_id) VALUES
    -- PII Patterns
    ('kw-ssn', '\d{3}-\d{2}-\d{4}', 'REGEX', false, 'CONFIDENTIAL', 90, false, 'Social Security Number pattern', 'grp-pii'),
    ('kw-passport', '[A-Z]{1,2}\d{6,9}', 'REGEX', false, 'CONFIDENTIAL', 85, false, 'Passport number pattern', 'grp-pii'),

    -- Financial Patterns
    ('kw-cc-visa', '4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', 'REGEX', false, 'CONFIDENTIAL', 95, false, 'Visa credit card pattern', 'grp-financial'),
    ('kw-cc-mc', '5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', 'REGEX', false, 'CONFIDENTIAL', 95, false, 'Mastercard pattern', 'grp-financial'),

    -- Internal Codes (Hard Block)
    ('kw-internal001', 'internal001', 'EXACT', false, 'RESTRICTED', 100, true, 'Internal control code - HARD BLOCK', 'grp-internal'),
    ('kw-topsecret', 'TOP_SECRET', 'EXACT', false, 'RESTRICTED', 100, true, 'Top secret classification marker', 'grp-internal'),
    ('kw-donotshare', 'DO_NOT_SHARE', 'EXACT', false, 'RESTRICTED', 100, true, 'Explicit sharing prohibition', 'grp-internal'),

    -- Common Confidential Terms
    ('kw-confidential', 'confidential', 'PARTIAL', false, 'CONFIDENTIAL', 70, false, 'Contains word confidential', NULL),
    ('kw-proprietary', 'proprietary', 'PARTIAL', false, 'CONFIDENTIAL', 70, false, 'Contains word proprietary', NULL),
    ('kw-internal', 'internal use only', 'PARTIAL', false, 'PRIVATE', 60, false, 'Internal use marking', NULL)
ON CONFLICT DO NOTHING;

-- ============================================
-- UPDATE TRIGGER FOR KEYWORDS
-- ============================================
CREATE OR REPLACE FUNCTION update_keywords_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_keywords_updated_at ON keywords;
CREATE TRIGGER trigger_keywords_updated_at
    BEFORE UPDATE ON keywords
    FOR EACH ROW
    EXECUTE FUNCTION update_keywords_updated_at();

-- ============================================
-- UPDATE TRIGGER FOR CLASSIFIED FILES
-- ============================================
DROP TRIGGER IF EXISTS trigger_classified_files_updated_at ON classified_files;
CREATE TRIGGER trigger_classified_files_updated_at
    BEFORE UPDATE ON classified_files
    FOR EACH ROW
    EXECUTE FUNCTION update_keywords_updated_at();
