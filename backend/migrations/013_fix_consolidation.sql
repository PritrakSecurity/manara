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
