-- ============================================================
-- Manara DLP: repair missing schema for migrations 002-013
-- Safe to run multiple times (idempotent: IF NOT EXISTS /
-- ADD COLUMN IF NOT EXISTS / ON CONFLICT DO NOTHING).
-- Fixes 500 errors on /api/v1/incidents, /api/v1/events,
-- /api/v1/dspm/* and the classification rule engine.
-- ============================================================

-- >>>>> 002_add_is_default_to_policies.sql <<<<<
-- Add is_default column to policies table
ALTER TABLE policies ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_policies_is_default ON policies(is_default);



-- >>>>> 003_add_ad_configuration.sql <<<<<
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



-- >>>>> 004_keywords_file_management.sql <<<<<
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



-- >>>>> 005_approval_workflow_incidents.sql <<<<<
-- Migration 005: Approval Workflow and Enhanced Incidents
-- Created: 2026-01-07
-- Purpose: Owner-based authorization workflow and incident management

-- ============================================
-- APPROVAL REQUESTS TABLE
-- For owner-based authorization workflow
-- ============================================
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id VARCHAR(50) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    file_hash VARCHAR(64) NOT NULL,
    file_name VARCHAR(500),
    file_path TEXT,
    file_classification VARCHAR(50),

    -- Requester info
    requester_sid VARCHAR(255) NOT NULL,
    requester_username VARCHAR(255) NOT NULL,
    requester_email VARCHAR(255),
    requester_device_id VARCHAR(100),
    requester_hostname VARCHAR(255),

    -- Owner info
    owner_sid VARCHAR(255) NOT NULL,
    owner_username VARCHAR(255) NOT NULL,
    owner_email VARCHAR(255),

    -- Action details
    action_type VARCHAR(50) NOT NULL, -- UPLOAD|USB_TRANSFER|EMAIL_ATTACH|PRINT|COPY|CLOUD_SYNC
    destination_type VARCHAR(50),
    destination_detail TEXT,

    -- Request status
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING|APPROVED|DENIED|TIMEOUT|CANCELLED
    decision_comment TEXT,
    allow_permanent BOOLEAN DEFAULT FALSE, -- Cache decision for future

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ NOT NULL,
    notified_at TIMESTAMPTZ,
    reminder_sent BOOLEAN DEFAULT FALSE,

    -- Policy context
    policy_id UUID,
    rule_id VARCHAR(50),

    CONSTRAINT approval_action_type_check CHECK (action_type IN ('UPLOAD', 'USB_TRANSFER', 'EMAIL_ATTACH', 'PRINT', 'COPY', 'CLOUD_SYNC', 'NETWORK_SHARE')),
    CONSTRAINT approval_status_check CHECK (status IN ('PENDING', 'APPROVED', 'DENIED', 'TIMEOUT', 'CANCELLED'))
);

-- Indexes for approval requests
CREATE INDEX IF NOT EXISTS idx_approval_owner_sid ON approval_requests(owner_sid);
CREATE INDEX IF NOT EXISTS idx_approval_owner_status ON approval_requests(owner_sid, status);
CREATE INDEX IF NOT EXISTS idx_approval_requester_sid ON approval_requests(requester_sid);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_timeout ON approval_requests(timeout_at) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_approval_created ON approval_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_file_hash ON approval_requests(file_hash);

-- ============================================
-- CACHED APPROVALS TABLE
-- Store permanent approval decisions
-- ============================================
CREATE TABLE IF NOT EXISTS cached_approvals (
    id BIGSERIAL PRIMARY KEY,
    file_hash VARCHAR(64) NOT NULL,
    user_sid VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    destination_pattern TEXT, -- Regex or exact match for destination
    approved_by_sid VARCHAR(255) NOT NULL,
    approved_by_username VARCHAR(255) NOT NULL,
    approval_comment TEXT,
    expires_at TIMESTAMPTZ, -- NULL = never expires
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(file_hash, user_sid, action_type, destination_pattern)
);

CREATE INDEX IF NOT EXISTS idx_cached_approvals_lookup ON cached_approvals(file_hash, user_sid, action_type);

-- ============================================
-- ENHANCED INCIDENTS TABLE
-- Comprehensive incident tracking and investigation
-- ============================================
CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(50) UNIQUE DEFAULT 'INC-' || gen_random_uuid()::text,

    -- Timing
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Severity and classification
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM', -- LOW|MEDIUM|HIGH|CRITICAL
    category VARCHAR(50) DEFAULT 'DATA_EXFILTRATION', -- DATA_EXFILTRATION|POLICY_VIOLATION|SUSPICIOUS_ACTIVITY|MALWARE

    -- Device info
    device_id VARCHAR(100),
    hostname VARCHAR(255),
    ip_address INET,

    -- User info
    user_sid VARCHAR(255),
    username VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    user_department VARCHAR(255),

    -- File info
    file_hash VARCHAR(64),
    file_name VARCHAR(500),
    file_path TEXT,
    file_size BIGINT,
    file_type VARCHAR(50),
    file_classification VARCHAR(50),

    -- Action details
    action_attempted VARCHAR(50) NOT NULL, -- UPLOAD|COPY|MOVE|PRINT|EMAIL|USB_TRANSFER|CLOUD_SYNC
    destination_type VARCHAR(50),
    destination_detail TEXT,

    -- Decision
    decision VARCHAR(20) NOT NULL, -- ALLOW|BLOCK|PENDING_APPROVAL
    block_reason TEXT,
    matched_keywords TEXT[],

    -- Policy info
    policy_id UUID,
    policy_name VARCHAR(255),
    rule_id VARCHAR(50),
    rule_name VARCHAR(255),

    -- Approval tracking
    approval_request_id VARCHAR(50),

    -- Investigation status
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN', -- OPEN|INVESTIGATING|ESCALATED|RESOLVED|FALSE_POSITIVE|ACKNOWLEDGED
    assigned_to VARCHAR(255),
    assigned_at TIMESTAMPTZ,
    escalated_to VARCHAR(255),
    escalated_at TIMESTAMPTZ,

    -- Investigation notes
    investigation_notes TEXT,
    resolution_notes TEXT,
    resolved_at TIMESTAMPTZ,
    resolved_by VARCHAR(255),

    -- Metadata
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT incidents_severity_check CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT incidents_status_check CHECK (status IN ('OPEN', 'INVESTIGATING', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE', 'ACKNOWLEDGED')),
    CONSTRAINT incidents_decision_check CHECK (decision IN ('ALLOW', 'BLOCK', 'PENDING_APPROVAL'))
);

-- Indexes for incidents
CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_user_sid ON incidents(user_sid);
CREATE INDEX IF NOT EXISTS idx_incidents_device_id ON incidents(device_id);
CREATE INDEX IF NOT EXISTS idx_incidents_decision ON incidents(decision);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents(assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incidents_file_hash ON incidents(file_hash);
CREATE INDEX IF NOT EXISTS idx_incidents_policy_id ON incidents(policy_id);
CREATE INDEX IF NOT EXISTS idx_incidents_open ON incidents(status, severity DESC) WHERE status = 'OPEN';

-- GIN index for tags and metadata
CREATE INDEX IF NOT EXISTS idx_incidents_tags ON incidents USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_incidents_metadata ON incidents USING GIN (metadata);

-- ============================================
-- INCIDENT NOTES TABLE
-- Track investigation activity
-- ============================================
CREATE TABLE IF NOT EXISTS incident_notes (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_username VARCHAR(255) NOT NULL,
    note_type VARCHAR(50) DEFAULT 'COMMENT', -- COMMENT|STATUS_CHANGE|ASSIGNMENT|ESCALATION|RESOLUTION
    content TEXT NOT NULL,
    previous_status VARCHAR(30),
    new_status VARCHAR(30),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_notes_created ON incident_notes(created_at DESC);

-- ============================================
-- INCIDENT STATISTICS VIEW
-- For dashboard metrics
-- ============================================
CREATE OR REPLACE VIEW incident_stats AS
SELECT
    DATE(timestamp) as date,
    severity,
    status,
    decision,
    COUNT(*) as count
FROM incidents
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY DATE(timestamp), severity, status, decision
ORDER BY date DESC, severity;

-- ============================================
-- PENDING APPROVALS VIEW
-- Quick access to pending approval requests
-- ============================================
CREATE OR REPLACE VIEW pending_approvals AS
SELECT
    ar.*,
    cf.classification as actual_classification,
    cf.matched_keywords,
    EXTRACT(EPOCH FROM (ar.timeout_at - NOW())) as seconds_remaining
FROM approval_requests ar
LEFT JOIN classified_files cf ON ar.file_hash = cf.file_hash
WHERE ar.status = 'PENDING'
    AND ar.timeout_at > NOW()
ORDER BY ar.created_at DESC;

-- ============================================
-- UPDATE TRIGGER FOR INCIDENTS
-- ============================================
CREATE OR REPLACE FUNCTION update_incidents_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_incidents_updated_at ON incidents;
CREATE TRIGGER trigger_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_incidents_updated_at();

-- ============================================
-- FUNCTION: CHECK APPROVAL TIMEOUT
-- Called periodically to timeout pending requests
-- ============================================
CREATE OR REPLACE FUNCTION process_approval_timeouts()
RETURNS INTEGER AS $$
DECLARE
    timeout_count INTEGER;
BEGIN
    UPDATE approval_requests
    SET status = 'TIMEOUT',
        decided_at = NOW()
    WHERE status = 'PENDING'
        AND timeout_at <= NOW();

    GET DIAGNOSTICS timeout_count = ROW_COUNT;
    RETURN timeout_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- ENHANCE AUDIT LOGS TABLE
-- Add more detailed tracking
-- ============================================
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS resource_name VARCHAR(255);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS old_value JSONB;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS new_value JSONB;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS session_id VARCHAR(100);

-- ============================================
-- NOTIFICATION QUEUE TABLE
-- For real-time notifications
-- ============================================
CREATE TABLE IF NOT EXISTS notification_queue (
    id BIGSERIAL PRIMARY KEY,
    recipient_sid VARCHAR(255) NOT NULL,
    recipient_email VARCHAR(255),
    notification_type VARCHAR(50) NOT NULL, -- APPROVAL_REQUEST|APPROVAL_DECISION|INCIDENT_ALERT|POLICY_CHANGE
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    data JSONB,
    priority VARCHAR(20) DEFAULT 'NORMAL', -- LOW|NORMAL|HIGH|URGENT
    channel VARCHAR(50) DEFAULT 'WEBSOCKET', -- WEBSOCKET|EMAIL|SMS|WEBHOOK
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING|SENT|FAILED|ACKNOWLEDGED
    retry_count INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    error_message TEXT,

    CONSTRAINT notification_type_check CHECK (notification_type IN ('APPROVAL_REQUEST', 'APPROVAL_DECISION', 'INCIDENT_ALERT', 'POLICY_CHANGE', 'SYSTEM_ALERT')),
    CONSTRAINT notification_priority_check CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')),
    CONSTRAINT notification_status_check CHECK (status IN ('PENDING', 'SENT', 'FAILED', 'ACKNOWLEDGED'))
);

CREATE INDEX IF NOT EXISTS idx_notification_recipient ON notification_queue(recipient_sid);
CREATE INDEX IF NOT EXISTS idx_notification_status ON notification_queue(status) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_notification_created ON notification_queue(created_at DESC);

-- ============================================
-- REPORTS TABLE
-- Store generated reports
-- ============================================
CREATE TABLE IF NOT EXISTS reports (
    id BIGSERIAL PRIMARY KEY,
    report_id VARCHAR(50) UNIQUE DEFAULT 'RPT-' || gen_random_uuid()::text,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    report_type VARCHAR(50) NOT NULL, -- DAILY_SUMMARY|POLICY_EFFECTIVENESS|USER_BEHAVIOR|COMPLIANCE|INCIDENT_RESPONSE|CUSTOM
    template_id VARCHAR(50),
    parameters JSONB DEFAULT '{}',
    filters JSONB DEFAULT '{}',
    date_range_start TIMESTAMPTZ,
    date_range_end TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING|GENERATING|COMPLETED|FAILED
    file_path TEXT,
    file_size BIGINT,
    format VARCHAR(20) DEFAULT 'PDF', -- PDF|CSV|JSON|XLSX
    generated_by VARCHAR(255) NOT NULL,
    generated_at TIMESTAMPTZ,
    scheduled BOOLEAN DEFAULT FALSE,
    schedule_cron VARCHAR(100),
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT reports_type_check CHECK (report_type IN ('DAILY_SUMMARY', 'POLICY_EFFECTIVENESS', 'USER_BEHAVIOR', 'COMPLIANCE', 'INCIDENT_RESPONSE', 'CUSTOM')),
    CONSTRAINT reports_status_check CHECK (status IN ('PENDING', 'GENERATING', 'COMPLETED', 'FAILED')),
    CONSTRAINT reports_format_check CHECK (format IN ('PDF', 'CSV', 'JSON', 'XLSX'))
);

CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_generated_by ON reports(generated_by);
CREATE INDEX IF NOT EXISTS idx_reports_scheduled ON reports(scheduled, next_run_at) WHERE scheduled = TRUE;



-- >>>>> 007_nmap_discovery.sql <<<<<
-- Add discovery_method and OS columns to devices
ALTER TABLE devices ADD COLUMN IF NOT EXISTS discovery_method VARCHAR(50) DEFAULT 'legacy';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os VARCHAR(255);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_version VARCHAR(255);

-- device_ports table
CREATE TABLE IF NOT EXISTS device_ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(255) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    state VARCHAR(20) NOT NULL,
    service VARCHAR(100),
    version VARCHAR(255),
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_port ON device_ports (device_id, port);
CREATE INDEX IF NOT EXISTS idx_port_state ON device_ports (port, state);

-- discovery_config table
CREATE TABLE IF NOT EXISTS discovery_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nmap_enabled BOOLEAN DEFAULT FALSE,
    nmap_binary_path VARCHAR(255) DEFAULT '/usr/bin/nmap',
    scan_mode VARCHAR(50) DEFAULT 'balanced',
    scan_interval_hours INT DEFAULT 24,
    max_hosts_per_scan INT DEFAULT 256,
    monitored_subnets TEXT[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO discovery_config (nmap_enabled, scan_mode, monitored_subnets)
VALUES (FALSE, 'balanced', ARRAY['192.168.1.0/24'])
ON CONFLICT DO NOTHING;

-- scan_history table
CREATE TABLE IF NOT EXISTS scan_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type VARCHAR(50) NOT NULL,
    subnet VARCHAR(100) NOT NULL,
    hosts_discovered INT DEFAULT 0,
    scan_duration_seconds FLOAT,
    status VARCHAR(50),
    error_message TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);



-- >>>>> 008_event_logging.sql <<<<<
-- Event logs and incidents for DLP (migration 008)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Event logs table (immutable, append-only for audit trail)
CREATE TABLE IF NOT EXISTS event_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(255) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    file_path TEXT NOT NULL,
    file_name VARCHAR(512) NOT NULL,
    file_size BIGINT,
    file_extension VARCHAR(50),
    source_location TEXT,
    destination_location TEXT,
    classification VARCHAR(50),
    risk_level VARCHAR(20),
    keywords_found TEXT[] DEFAULT '{}',
    process_name VARCHAR(255),
    username VARCHAR(255),
    operation_result VARCHAR(50),
    was_blocked BOOLEAN DEFAULT FALSE,
    block_reason VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_event_logs_device_created ON event_logs (device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_event_logs_event_type ON event_logs (event_type);
CREATE INDEX IF NOT EXISTS idx_event_logs_classification ON event_logs (classification);
CREATE INDEX IF NOT EXISTS idx_event_logs_risk_level ON event_logs (risk_level);
CREATE INDEX IF NOT EXISTS idx_event_logs_username ON event_logs (username);
CREATE INDEX IF NOT EXISTS idx_event_logs_file_extension ON event_logs (file_extension);

-- DLP Rules engine table
CREATE TABLE IF NOT EXISTS dlp_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50),
    conditions TEXT NOT NULL,
    action VARCHAR(50) NOT NULL,
    severity VARCHAR(20),
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default DLP rules (best-effort)
INSERT INTO dlp_rules (name, rule_type, conditions, action, severity, description)
VALUES
('USB Copy High Risk Files','FILE_TRANSFER','{"event_type":"USB_COPY","classification":["CONFIDENTIAL","RESTRICTED"],"risk_level":["HIGH","CRITICAL"]}','BLOCK_AND_ALERT','HIGH','Block copying confidential files to USB drives'),
('Sensitive File Deletion','FILE_OPERATION','{"event_type":"DELETE","classification":["CONFIDENTIAL","RESTRICTED"]}','ALERT_ONLY','MEDIUM','Alert on deletion of sensitive files'),
('Database File Access','FILE_ACCESS','{"file_extension":["db","sql","mdb","sqlite"],"keywords_found":["password","key","secret"]}','BLOCK_AND_ALERT','CRITICAL','Block access to database files containing credentials'),
('Email Archive Copy','FILE_TRANSFER','{"event_type":["COPY","USB_COPY"],"file_extension":["pst","ost","eml"]}','BLOCK_AND_ALERT','HIGH','Block copying email archives'),
('Financial Document USB Transfer','FILE_TRANSFER','{"event_type":"USB_COPY","keywords_found":["financial","invoice","contract","salary","budget","credit_card","ssn"]}','BLOCK_AND_ALERT','CRITICAL','Block sensitive financial documents to USB'),
('Mass File Copy','FILE_OPERATION','{"event_type":"COPY","consecutive_events":5,"time_window_seconds":60}','ALERT_ONLY','MEDIUM','Alert on bulk file copy operations'),
('Executable Download','FILE_OPERATION','{"event_type":"CREATE","file_extension":["exe","dll","sys","bat","ps1","scr"],"source_location":["Downloads"]}','ALERT_ONLY','MEDIUM','Alert on executable downloads'),
('Restricted File Rename','FILE_OPERATION','{"event_type":"RENAME","classification":"RESTRICTED"}','ALERT_ONLY','LOW','Alert on renaming restricted files')
ON CONFLICT DO NOTHING;



-- >>>>> 009_settings.sql <<<<<
-- Create settings table to persist application settings as JSON
CREATE TABLE IF NOT EXISTS settings (
    id VARCHAR(255) PRIMARY KEY,
    key VARCHAR(128) NOT NULL UNIQUE,
    value JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed a default 'system' settings record
INSERT INTO settings (id, key, value)
VALUES ('settings-system', 'system', '{"systemName":"PRITRAK DLP","timezone":"UTC","dateFormat":"YYYY-MM-DD","sessionTimeout":30,"maxLoginAttempts":5,"passwordPolicy":"strong","mfaRequired":true,"dataRetentionDays":90}')
ON CONFLICT (key) DO NOTHING;



-- >>>>> 010_classification_rules.sql <<<<<
-- Classification Rules System (V3.0)
-- Enables admins to create custom rules for file classification

CREATE TABLE IF NOT EXISTS classification_rules (
    id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    
    -- Condition (what triggers the rule)
    condition_field TEXT NOT NULL,
    condition_operator TEXT NOT NULL,
    condition_value TEXT NOT NULL,
    
    -- Action (what happens when rule triggers)
    action_type TEXT NOT NULL DEFAULT 'classify_as',
    action_classification TEXT,
    
    -- Metadata
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_system BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_rules_priority ON classification_rules(priority, enabled);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON classification_rules(enabled);

CREATE TABLE IF NOT EXISTS rule_audit_log (
    id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    rule_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    old_classification TEXT,
    new_classification TEXT,
    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(rule_id) REFERENCES classification_rules(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_log_rule_id ON rule_audit_log(rule_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_file_path ON rule_audit_log(file_path);

-- Insert default system rules (examples)
INSERT INTO classification_rules 
(name, description, enabled, priority, condition_field, condition_operator, condition_value, action_type, action_classification, is_system, created_by)
VALUES 
('Source Code Files', 'Automatically classify source code as INTERNAL', TRUE, 50, 'file_extension', 'in_list', '.cpp,.py,.js,.java,.ts,.go,.rs', 'classify_as', 'INTERNAL', TRUE, 'system'),
('Password Files', 'Automatically classify password files as RESTRICTED', TRUE, 10, 'keyword', 'matches_regex', '^.*\.(key|pem|p12|pfx|ppk|env)$', 'classify_as', 'RESTRICTED', TRUE, 'system'),
('Database Backups', 'Automatically classify database backups as RESTRICTED', TRUE, 20, 'file_extension', 'in_list', '.sql,.sql.bak,.backup', 'classify_as', 'RESTRICTED', TRUE, 'system')
ON CONFLICT (name) DO NOTHING;



-- >>>>> 011_device_improvements.sql <<<<<
-- Device Lifecycle Improvements
-- Adds additional tracking fields for device management

-- Add is_registered field if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='devices' AND column_name='is_registered') THEN
        ALTER TABLE devices ADD COLUMN is_registered BOOLEAN DEFAULT true;
    END IF;
END $$;

-- Add last_heartbeat_time field if not exists  
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='devices' AND column_name='last_heartbeat_time') THEN
        ALTER TABLE devices ADD COLUMN last_heartbeat_time TIMESTAMP;
    END IF;
END $$;

-- Update existing devices to have heartbeat time match last_seen
UPDATE devices SET last_heartbeat_time = last_seen WHERE last_heartbeat_time IS NULL;

-- Add index for heartbeat monitoring
CREATE INDEX IF NOT EXISTS idx_devices_heartbeat ON devices(last_heartbeat_time DESC);
CREATE INDEX IF NOT EXISTS idx_devices_is_registered ON devices(is_registered);

-- Update all existing devices to be registered
UPDATE devices SET is_registered = true WHERE is_registered IS NULL;

-- Create device_logs table for tracking device events
CREATE TABLE IF NOT EXISTS device_logs (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(255) NOT NULL,
    log_level VARCHAR(20) NOT NULL DEFAULT 'INFO',
    category VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_logs_device_id ON device_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_device_logs_timestamp ON device_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_device_logs_level ON device_logs(log_level);
CREATE INDEX IF NOT EXISTS idx_device_logs_category ON device_logs(category);

-- Create audit_logs table if not exists (for tracking system events)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    details TEXT,
    device_id VARCHAR(255),
    hostname VARCHAR(255),
    ip_address VARCHAR(45),
    agent_version VARCHAR(50),
    user_id VARCHAR(255),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Existing audit_logs may predate this schema (created by 001_init.sql); add
-- the columns the backend (devices.go) writes to.
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS event_type VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS device_id VARCHAR(255);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hostname VARCHAR(255);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS agent_version VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_device_id ON audit_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred_at ON audit_logs(occurred_at DESC);

-- Insert initial log entries for existing devices
INSERT INTO device_logs (device_id, log_level, category, message, timestamp)
SELECT id, 'INFO', 'SYSTEM', 'Device registered in system', registered_at
FROM devices
WHERE id NOT IN (SELECT DISTINCT device_id FROM device_logs WHERE category = 'SYSTEM');

-- Comment for documentation
COMMENT ON TABLE device_logs IS 'Stores logs and events for each registered device';
COMMENT ON TABLE audit_logs IS 'Stores system-wide audit trail for compliance and debugging';



-- >>>>> 013_fix_consolidation.sql <<<<<
CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(50) UNIQUE DEFAULT 'INC-' || gen_random_uuid()::text,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    category VARCHAR(50) DEFAULT 'DATA_EXFILTRATION',
    device_id VARCHAR(100),
    hostname VARCHAR(255),
    ip_address INET,
    user_sid VARCHAR(255),
    username VARCHAR(255) NOT NULL DEFAULT 'unknown',
    user_email VARCHAR(255),
    user_department VARCHAR(255),
    file_hash VARCHAR(64),
    file_name VARCHAR(500),
    file_path TEXT,
    file_size BIGINT,
    file_type VARCHAR(50),
    file_classification VARCHAR(50),
    action_attempted VARCHAR(50) NOT NULL DEFAULT 'UNKNOWN',
    destination_type VARCHAR(50),
    destination_detail TEXT,
    decision VARCHAR(20) NOT NULL DEFAULT 'BLOCK',
    block_reason TEXT,
    matched_keywords TEXT[],
    policy_id UUID,
    policy_name VARCHAR(255),
    rule_id VARCHAR(50),
    rule_name VARCHAR(255),
    approval_request_id VARCHAR(50),
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    assigned_to VARCHAR(255),
    assigned_at TIMESTAMPTZ,
    escalated_to VARCHAR(255),
    escalated_at TIMESTAMPTZ,
    investigation_notes TEXT,
    resolution_notes TEXT,
    resolved_at TIMESTAMPTZ,
    resolved_by VARCHAR(255),
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS event_id UUID REFERENCES event_logs(id) ON DELETE SET NULL;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS incident_type VARCHAR(100);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS rule_triggered_reason TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS file_involved TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS user_involved VARCHAR(255);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS action_taken VARCHAR(100);

CREATE INDEX IF NOT EXISTS idx_incidents_event_id ON incidents (event_id);
CREATE INDEX IF NOT EXISTS idx_incidents_incident_type ON incidents (incident_type);



