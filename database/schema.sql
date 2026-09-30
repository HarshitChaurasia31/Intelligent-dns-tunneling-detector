-- PostgreSQL schema for DNS Tunneling Detection SOC Incidents (v1)

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_start BIGINT NOT NULL,
    window_end BIGINT NOT NULL CHECK (window_end >= window_start),
    triggered_rules JSONB NOT NULL,
    score_breakdown JSONB NOT NULL,
    evidence JSONB NOT NULL,
    summary TEXT NOT NULL,
    investigation JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents (source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_window_start ON incidents (window_start);
