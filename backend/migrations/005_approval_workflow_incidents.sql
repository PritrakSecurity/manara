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
