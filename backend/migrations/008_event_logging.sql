-- Event logs and incidents for DLP (migration 008)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Event logs table (immutable, append-only for audit trail)
CREATE TABLE IF NOT EXISTS event_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
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
