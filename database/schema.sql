-- AI Work Management System - Phase 1 Database Schema
-- D1 Database setup for authentication and organizations

-- Organizations table
CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    settings TEXT DEFAULT '{}',
    subscription_tier TEXT DEFAULT 'free',
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Users with role-based access
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    organization_id TEXT REFERENCES organizations(id),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    role TEXT CHECK (role IN ('ceo', 'manager', 'employee')) NOT NULL,
    skills TEXT DEFAULT '[]',
    capacity_hours_per_week INTEGER DEFAULT 40,
    calendar_connected INTEGER DEFAULT 0,
    calendar_provider TEXT,
    avatar_url TEXT,
    is_active INTEGER DEFAULT 1,
    last_login INTEGER,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- GDPR compliance tracking
CREATE TABLE gdpr_consents (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    consent_type TEXT NOT NULL,
    granted INTEGER NOT NULL,
    timestamp INTEGER DEFAULT (strftime('%s', 'now')),
    ip_address TEXT,
    user_agent TEXT
);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Audit log for security
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    organization_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    metadata TEXT DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    timestamp INTEGER DEFAULT (strftime('%s', 'now'))
);

-- User sessions (for tracking multiple devices)
CREATE TABLE user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    session_token TEXT NOT NULL,
    device_info TEXT,
    ip_address TEXT,
    last_activity INTEGER DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Indexes for performance
CREATE INDEX idx_users_org ON users(organization_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_gdpr_user ON gdpr_consents(user_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_org ON audit_logs(organization_id);
CREATE INDEX idx_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_sessions_token ON user_sessions(session_token);

-- Insert default organization for testing
INSERT INTO organizations (id, name, settings) 
VALUES ('default-org', 'Default Organization', '{"timezone": "UTC", "work_hours": {"start": 9, "end": 17}}');