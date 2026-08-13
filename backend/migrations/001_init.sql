-- DLP Platform Database Schema
-- Version: 1.0
-- Created: 2024-03-15

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    rules JSONB NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL,
    
    CONSTRAINT policies_name_unique UNIQUE (name)
);

-- Create index on policies for faster queries
CREATE INDEX IF NOT EXISTS idx_policies_enabled_priority ON policies(enabled, priority DESC);
CREATE INDEX IF NOT EXISTS idx_policies_created_at ON policies(created_at DESC);

-- Endpoints table (registered agents)
CREATE TABLE IF NOT EXISTS endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id TEXT UNIQUE NOT NULL,
    hostname TEXT,
    ip_address INET,
    os_version TEXT,
    agent_version TEXT,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'active',
    
    CONSTRAINT endpoints_agent_id_unique UNIQUE (agent_id)
);

-- Create index on endpoints
CREATE INDEX IF NOT EXISTS idx_endpoints_agent_id ON endpoints(agent_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);

-- Telemetry events table
CREATE TABLE IF NOT EXISTS telemetry_events (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES endpoints(agent_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    operation TEXT,
    source_path TEXT,
    destination TEXT,
    application TEXT,
    user_id TEXT,
    data JSONB,
    severity TEXT NOT NULL DEFAULT 'INFO',
    action_taken TEXT NOT NULL,
    policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
    rule_id TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT telemetry_events_severity_check CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT telemetry_events_action_check CHECK (action_taken IN ('ALLOW', 'BLOCK', 'LOG', 'QUARANTINE', 'ENCRYPT', 'REDACT'))
);

-- Create indexes on telemetry_events for performance
CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_agent_id ON telemetry_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_event_type ON telemetry_events(event_type);
CREATE INDEX IF NOT EXISTS idx_telemetry_severity ON telemetry_events(severity);
CREATE INDEX IF NOT EXISTS idx_telemetry_action_taken ON telemetry_events(action_taken);
CREATE INDEX IF NOT EXISTS idx_telemetry_policy_id ON telemetry_events(policy_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_user_id ON telemetry_events(user_id);

-- GIN index for JSONB data field (for efficient JSON queries)
CREATE INDEX IF NOT EXISTS idx_telemetry_data_gin ON telemetry_events USING GIN (data);

-- Policy violations table (for tracking blocked operations)
CREATE TABLE IF NOT EXISTS policy_violations (
    id BIGSERIAL PRIMARY KEY,
    event_id BIGINT REFERENCES telemetry_events(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
    rule_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    violation_type TEXT NOT NULL,
    data_classification TEXT[],
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolved_at TIMESTAMPTZ,
    resolved_by TEXT,
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes on policy_violations
CREATE INDEX IF NOT EXISTS idx_violations_agent_id ON policy_violations(agent_id);
CREATE INDEX IF NOT EXISTS idx_violations_policy_id ON policy_violations(policy_id);
CREATE INDEX IF NOT EXISTS idx_violations_user_id ON policy_violations(user_id);
CREATE INDEX IF NOT EXISTS idx_violations_resolved ON policy_violations(resolved, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_created_at ON policy_violations(created_at DESC);

-- Users table (for admin console)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Viewer',
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT users_role_check CHECK (role IN ('SuperAdmin', 'PolicyAdmin', 'SecurityAnalyst', 'Viewer'))
);

-- Create index on users
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Audit log table (for tracking admin actions)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index on audit_logs
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

-- Insert default policy (fail-closed)
INSERT INTO policies (id, name, description, rules, priority, enabled, created_by)
VALUES (
    uuid_generate_v4(),
    'Default Policy',
    'Default fail-closed policy - blocks all operations when no other policy matches',
    '{"rules": [{"rule_id": "default-deny", "name": "Default Deny", "priority": 0, "enabled": true, "action": "BLOCK", "conditions": {}, "description": "Default fail-closed policy"}]}'::jsonb,
    0,
    true,
    'system'
) ON CONFLICT DO NOTHING;

-- Insert default admin user (password should be changed on first login)
-- Password hash for 'admin' (bcrypt, rounds=10)
-- In production, this should be set via environment variable or initial setup
INSERT INTO users (id, username, email, password_hash, role, enabled)
VALUES (
    uuid_generate_v4(),
    'admin',
    'admin@example.com',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', -- 'admin' password
    'SuperAdmin',
    true
) ON CONFLICT DO NOTHING;

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at for policies
CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger to auto-update updated_at for users
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to update endpoint last_seen
CREATE OR REPLACE FUNCTION update_endpoint_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_seen = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- View for recent violations (last 24 hours)
CREATE OR REPLACE VIEW recent_violations AS
SELECT 
    pv.id,
    pv.agent_id,
    e.hostname,
    pv.user_id,
    pv.violation_type,
    pv.data_classification,
    pv.created_at,
    p.name as policy_name,
    pv.rule_id
FROM policy_violations pv
LEFT JOIN endpoints e ON pv.agent_id = e.agent_id
LEFT JOIN policies p ON pv.policy_id = p.id
WHERE pv.created_at >= NOW() - INTERVAL '24 hours'
  AND pv.resolved = false
ORDER BY pv.created_at DESC;

-- View for policy statistics
CREATE OR REPLACE VIEW policy_stats AS
SELECT 
    p.id,
    p.name,
    p.enabled,
    COUNT(DISTINCT te.id) as total_events,
    COUNT(DISTINCT CASE WHEN te.action_taken = 'BLOCK' THEN te.id END) as blocked_events,
    COUNT(DISTINCT pv.id) as violations
FROM policies p
LEFT JOIN telemetry_events te ON te.policy_id = p.id
LEFT JOIN policy_violations pv ON pv.policy_id = p.id
GROUP BY p.id, p.name, p.enabled;
