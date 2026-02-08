-- RanScanAI initial schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- System Providers table
CREATE TABLE IF NOT EXISTS System_Providers (
    provider_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_name TEXT NOT NULL,
    provider_position TEXT,
    provider_email TEXT UNIQUE
);

-- Companies table
CREATE TABLE IF NOT EXISTS Companies (
    company_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID REFERENCES System_Providers(provider_id),
    company_name TEXT NOT NULL,
    company_industry TEXT,
    company_size TEXT,
    company_email TEXT,
    register_date TIMESTAMP DEFAULT now(),
    subscription_start TIMESTAMP,
    subscription_end TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Company Statistics table
CREATE TABLE IF NOT EXISTS Company_Stat (
    stat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID REFERENCES Companies(company_id),
    stat_date DATE,
    stat_time TIME,
    active_users INT,
    total_detections INT,
    time_period TEXT
);

-- Registrations table
CREATE TABLE IF NOT EXISTS Registrations (
    registration_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID REFERENCES System_Providers(provider_id),
    company_id UUID REFERENCES Companies(company_id),
    request_date TIMESTAMP DEFAULT now(),
    request_status TEXT,
    company_name TEXT,
    company_industry TEXT,
    company_size TEXT,
    company_email TEXT
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone_number TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    role TEXT NOT NULL DEFAULT 'developer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

-- Devices table
CREATE TABLE IF NOT EXISTS Devices (
    device_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES Users(user_id),
    device_name TEXT NOT NULL,
    os_version TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

-- Models table
CREATE TABLE IF NOT EXISTS models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version TEXT NOT NULL,
    file_name TEXT,
    accuracy REAL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    notes TEXT
);

-- Detections table
CREATE TABLE IF NOT EXISTS Detections (
    detection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES Devices(device_id),
    detection_name TEXT,
    detection_time TIMESTAMP DEFAULT now(),
    confidence_score FLOAT,
    status TEXT,
    file_name TEXT,
    message TEXT,
    mitigation_suggestion TEXT,
    is_ransomware BOOLEAN
);

-- Static Features table
CREATE TABLE IF NOT EXISTS Static_Features (
    static_feature_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES Detections(detection_id),
    file_header TEXT,
    file_type TEXT,
    file_size BIGINT,
    file_entropy FLOAT,
    file_path TEXT,
    sha256 TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Dynamic Features table
CREATE TABLE IF NOT EXISTS Dynamic_Features (
    dynamic_feature_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES Detections(detection_id),
    api_call_name TEXT,
    api_call_count INT
);

-- ---------------------------
-- Alerts
-- ---------------------------
CREATE TABLE IF NOT EXISTS Alerts (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES Detections(detection_id),
    alert_time TIMESTAMP DEFAULT now(),
    message TEXT
);

-- ---------------------------
-- Alert Receivers
-- ---------------------------
CREATE TABLE IF NOT EXISTS Alert_Receivers (
    alert_id UUID REFERENCES Alerts(alert_id),
    user_id UUID REFERENCES Users(user_id),
    is_read BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (alert_id, user_id)
);

-- ---------------------------
-- Reports
-- ---------------------------
CREATE TABLE IF NOT EXISTS Reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES Users(user_id),
    detection_id UUID REFERENCES Detections(detection_id),
    created_at TIMESTAMP DEFAULT now(),
    period_start TIMESTAMP,
    period_end TIMESTAMP,
    detection_count INT,
    message TEXT,
    is_sent BOOLEAN DEFAULT FALSE
);

-- ---------------------------
-- Summary Reports
-- ---------------------------
CREATE TABLE IF NOT EXISTS Summary_Reports (
    summary_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES Users(user_id),
    detection_id UUID REFERENCES Detections(detection_id),
    created_at TIMESTAMP DEFAULT now(),
    period_start TIMESTAMP,
    period_end TIMESTAMP,
    detection_count INT,
    message TEXT,
    user_device_summary TEXT,
    mitigation_suggestion TEXT,
    is_sent BOOLEAN DEFAULT FALSE
);

-- ---------------------------
-- Uncertain Sample Reviews
-- ---------------------------
CREATE TABLE IF NOT EXISTS Uncertain_Sample_Reviews (
    review_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES Detections(detection_id),
    provider_id UUID REFERENCES System_Providers(provider_id),
    label TEXT,
    detection_time TIMESTAMP,
    confidence_score FLOAT,
    status TEXT,
    review_time TIMESTAMP DEFAULT now()
);

-- -- Files table
-- CREATE TABLE IF NOT EXISTS files (
--     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     file_name TEXT NOT NULL,
--     file_path TEXT,
--     size_bytes BIGINT,
--     sha256 TEXT,
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
-- );

-- -- Scans table
-- CREATE TABLE IF NOT EXISTS scans (
--     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     file_id UUID REFERENCES files(id) ON DELETE SET NULL,
--     scanned_by UUID REFERENCES users(id) ON DELETE SET NULL,
--     scanned_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
--     is_malicious BOOLEAN,
--     confidence REAL,
--     scan_time_ms REAL,
--     model_id UUID REFERENCES models(id),
--     raw_result JSONB,
--     vt_enriched BOOLEAN DEFAULT false
-- );

-- VirusTotal results
CREATE TABLE IF NOT EXISTS vt_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES Detections(detection_id) ON DELETE CASCADE,
    vt_json JSONB,
    vt_first_seen TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_file_id ON static_features(static_feature_id);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON static_features(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON detections(detection_time);
