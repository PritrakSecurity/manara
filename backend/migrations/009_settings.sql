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
