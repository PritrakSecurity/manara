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
