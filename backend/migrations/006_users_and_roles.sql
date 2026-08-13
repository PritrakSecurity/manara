-- Users and roles schema for PRITRAK DAP

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_ad_synced BOOLEAN DEFAULT FALSE,
    last_ad_sync TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User-Role mapping
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, role_id)
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Role-Permission mapping
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

-- Insert default permissions
INSERT INTO permissions (name, resource, action, description) VALUES
('policies.read', 'Policies', 'read', 'View DLP policies'),
('policies.create', 'Policies', 'create', 'Create new policies'),
('policies.update', 'Policies', 'update', 'Edit policies'),
('policies.delete', 'Policies', 'delete', 'Delete policies'),
('keywords.read', 'Keywords', 'read', 'View keywords'),
('keywords.create', 'Keywords', 'create', 'Add keywords'),
('keywords.update', 'Keywords', 'update', 'Edit keywords'),
('keywords.delete', 'Keywords', 'delete', 'Delete keywords'),
('incidents.read', 'Incidents', 'read', 'View incidents'),
('incidents.update', 'Incidents', 'update', 'Update incident details'),
('incidents.resolve', 'Incidents', 'resolve', 'Resolve incidents'),
('endpoints.read', 'Endpoints', 'read', 'View endpoints'),
('endpoints.manage', 'Endpoints', 'manage', 'Manage endpoints'),
('endpoints.delete', 'Endpoints', 'delete', 'Remove endpoints'),
('reports.read', 'Reports', 'read', 'View reports'),
('reports.generate', 'Reports', 'generate', 'Generate reports'),
('reports.schedule', 'Reports', 'schedule', 'Schedule reports'),
('settings.read', 'Settings', 'read', 'View settings'),
('settings.update', 'Settings', 'update', 'Modify settings')
ON CONFLICT DO NOTHING;

-- Insert default roles
INSERT INTO roles (name, description) VALUES
('Admin', 'Full system access'),
('Security Officer', 'Manage policies and incidents'),
('Analyst', 'View incidents and reports'),
('Auditor', 'Read-only access'),
('Agent Manager', 'Manage endpoints')
ON CONFLICT DO NOTHING;

-- Audit log for system events (including heartbeat successes/failures)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    details TEXT,
    device_id UUID,
    hostname VARCHAR(255),
    ip_address VARCHAR(45),
    agent_version VARCHAR(50),
    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
