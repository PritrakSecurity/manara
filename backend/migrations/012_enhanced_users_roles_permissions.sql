-- Enhanced Users, Roles & Permissions Management System for PRITRAK DLP
-- This migration enhances the existing users/roles system with additional features

-- Add missing columns to users table if they don't exist
DO $$ 
BEGIN
    -- Add password_hash for local users
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='password_hash') THEN
        ALTER TABLE users ADD COLUMN password_hash VARCHAR(255);
    END IF;
    
    -- Add source column to distinguish local vs AD users
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='source') THEN
        ALTER TABLE users ADD COLUMN source VARCHAR(50) DEFAULT 'local' NOT NULL;
    END IF;
    
    -- Add AD distinguished name
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='ad_distinguished_name') THEN
        ALTER TABLE users ADD COLUMN ad_distinguished_name VARCHAR(500);
    END IF;
    
    -- Add status column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='status') THEN
        ALTER TABLE users ADD COLUMN status VARCHAR(50) DEFAULT 'active';
    END IF;
    
    -- Add last_login
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='last_login') THEN
        ALTER TABLE users ADD COLUMN last_login TIMESTAMP;
    END IF;
    
    -- Add created_by
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='created_by') THEN
        ALTER TABLE users ADD COLUMN created_by UUID;
    END IF;
END $$;

-- Add is_system flag to roles table
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='roles' AND column_name='is_system') THEN
        ALTER TABLE roles ADD COLUMN is_system BOOLEAN DEFAULT FALSE;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='roles' AND column_name='created_by') THEN
        ALTER TABLE roles ADD COLUMN created_by UUID;
    END IF;
END $$;

-- Add is_implemented flag to permissions
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='permissions' AND column_name='is_implemented') THEN
        ALTER TABLE permissions ADD COLUMN is_implemented BOOLEAN DEFAULT TRUE;
    END IF;
END $$;

-- Add granted_by column to role_permissions
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='role_permissions' AND column_name='granted_by') THEN
        ALTER TABLE role_permissions ADD COLUMN granted_by UUID;
    END IF;
END $$;

-- Add assigned_by column to user_roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='user_roles' AND column_name='assigned_by') THEN
        ALTER TABLE user_roles ADD COLUMN assigned_by UUID;
    END IF;
END $$;

-- Update existing roles to mark system roles
UPDATE roles SET is_system = TRUE 
WHERE name IN ('Admin', 'Security Officer', 'Analyst', 'Auditor', 'Agent Manager');

-- Insert additional permissions for user management
INSERT INTO permissions (name, resource, action, description, is_implemented) VALUES
('users.read', 'Users', 'read', 'View user list and details', TRUE),
('users.create', 'Users', 'create', 'Add new users to the system', TRUE),
('users.update', 'Users', 'update', 'Edit user details and roles', TRUE),
('users.delete', 'Users', 'delete', 'Remove users from the system', TRUE),
('roles.read', 'Roles', 'read', 'View roles and their permissions', TRUE),
('roles.create', 'Roles', 'create', 'Create custom roles', TRUE),
('roles.update', 'Roles', 'update', 'Edit role permissions', TRUE),
('roles.delete', 'Roles', 'delete', 'Delete custom roles', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Assign all permissions to Admin role
DO $$
DECLARE
    admin_role_id UUID;
    perm_id UUID;
BEGIN
    -- Get Admin role ID
    SELECT id INTO admin_role_id FROM roles WHERE name = 'Admin' LIMIT 1;
    
    IF admin_role_id IS NOT NULL THEN
        -- Grant all permissions to Admin
        FOR perm_id IN SELECT id FROM permissions LOOP
            INSERT INTO role_permissions (role_id, permission_id, assigned_at)
            VALUES (admin_role_id, perm_id, NOW())
            ON CONFLICT DO NOTHING;
        END LOOP;
    END IF;
END $$;

-- Grant specific permissions to Security Officer
DO $$
DECLARE
    role_id UUID;
BEGIN
    SELECT id INTO role_id FROM roles WHERE name = 'Security Officer' LIMIT 1;
    
    IF role_id IS NOT NULL THEN
        INSERT INTO role_permissions (role_id, permission_id, assigned_at)
        SELECT role_id, p.id, NOW()
        FROM permissions p
        WHERE p.name IN (
            'incidents.read', 'incidents.update', 'incidents.resolve',
            'endpoints.read', 'reports.read',
            'policies.read', 'keywords.read'
        )
        ON CONFLICT DO NOTHING;
    END IF;
END $$;

-- Grant read-only permissions to Auditor
DO $$
DECLARE
    role_id UUID;
BEGIN
    SELECT id INTO role_id FROM roles WHERE name = 'Auditor' LIMIT 1;
    
    IF role_id IS NOT NULL THEN
        INSERT INTO role_permissions (role_id, permission_id, assigned_at)
        SELECT role_id, p.id, NOW()
        FROM permissions p
        WHERE p.action = 'read'
        ON CONFLICT DO NOTHING;
    END IF;
END $$;

-- Grant policy management permissions to Analyst
DO $$
DECLARE
    role_id UUID;
BEGIN
    SELECT id INTO role_id FROM roles WHERE name = 'Analyst' LIMIT 1;
    
    IF role_id IS NOT NULL THEN
        INSERT INTO role_permissions (role_id, permission_id, assigned_at)
        SELECT role_id, p.id, NOW()
        FROM permissions p
        WHERE p.name IN (
            'policies.read', 'policies.create', 'policies.update',
            'keywords.read', 'keywords.create', 'keywords.update',
            'incidents.read', 'reports.read'
        )
        ON CONFLICT DO NOTHING;
    END IF;
END $$;

-- Grant endpoint management to Agent Manager
DO $$
DECLARE
    role_id UUID;
BEGIN
    SELECT id INTO role_id FROM roles WHERE name = 'Agent Manager' LIMIT 1;
    
    IF role_id IS NOT NULL THEN
        INSERT INTO role_permissions (role_id, permission_id, assigned_at)
        SELECT role_id, p.id, NOW()
        FROM permissions p
        WHERE p.resource = 'Endpoints' OR p.name IN ('users.read', 'roles.read')
        ON CONFLICT DO NOTHING;
    END IF;
END $$;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_source ON users(source);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_ad_dn ON users(ad_distinguished_name);

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_is_system ON roles(is_system);

CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
