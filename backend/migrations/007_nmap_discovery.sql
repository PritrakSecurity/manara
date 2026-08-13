-- Add discovery_method and OS columns to devices
ALTER TABLE devices ADD COLUMN IF NOT EXISTS discovery_method VARCHAR(50) DEFAULT 'legacy';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os VARCHAR(255);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_version VARCHAR(255);

-- device_ports table
CREATE TABLE IF NOT EXISTS device_ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
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
