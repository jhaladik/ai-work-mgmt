-- AI Work Management System - Phase 2: Business Outcomes Schema
-- Extends the database with outcome tracking and AI analysis storage

-- Business outcomes table (CEO-defined goals)
CREATE TABLE business_outcomes (
    id TEXT PRIMARY KEY,
    organization_id TEXT REFERENCES organizations(id),
    created_by TEXT REFERENCES users(id),
    title TEXT NOT NULL,
    description TEXT,
    target_value TEXT NOT NULL,
    target_metric TEXT,
    timeline_start INTEGER NOT NULL,
    timeline_end INTEGER NOT NULL,
    priority TEXT CHECK (priority IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
    status TEXT CHECK (status IN ('draft', 'active', 'completed', 'cancelled')) DEFAULT 'draft',
    ai_analysis TEXT, -- Stored JSON from Claude analysis
    success_probability REAL,
    estimated_hours INTEGER,
    estimated_team_size INTEGER,
    actual_completion_date INTEGER,
    completion_notes TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Activities derived from AI backward planning
CREATE TABLE outcome_activities (
    id TEXT PRIMARY KEY,
    business_outcome_id TEXT REFERENCES business_outcomes(id),
    title TEXT NOT NULL,
    description TEXT,
    estimated_hours INTEGER,
    skills_required TEXT DEFAULT '[]', -- JSON array
    timeline_position TEXT, -- Q1, Q2, etc. or specific dates
    success_probability REAL,
    dependencies TEXT DEFAULT '[]', -- JSON array of activity IDs
    priority_order INTEGER,
    status TEXT CHECK (status IN ('pending', 'active', 'completed', 'blocked')) DEFAULT 'pending',
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Milestones for outcome tracking
CREATE TABLE outcome_milestones (
    id TEXT PRIMARY KEY,
    business_outcome_id TEXT REFERENCES business_outcomes(id),
    title TEXT NOT NULL,
    description TEXT,
    target_date INTEGER NOT NULL,
    completed_date INTEGER,
    deliverables TEXT DEFAULT '[]', -- JSON array
    status TEXT CHECK (status IN ('upcoming', 'due', 'completed', 'overdue')) DEFAULT 'upcoming',
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Risk factors identified by AI
CREATE TABLE outcome_risks (
    id TEXT PRIMARY KEY,
    business_outcome_id TEXT REFERENCES business_outcomes(id),
    risk_description TEXT NOT NULL,
    probability REAL, -- 0.0 to 1.0
    impact TEXT CHECK (impact IN ('low', 'medium', 'high', 'critical')),
    mitigation_strategy TEXT,
    status TEXT CHECK (status IN ('identified', 'monitoring', 'mitigated', 'occurred')) DEFAULT 'identified',
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- AI analysis cache for performance
CREATE TABLE ai_analysis_cache (
    id TEXT PRIMARY KEY,
    cache_key TEXT UNIQUE NOT NULL,
    analysis_type TEXT NOT NULL, -- 'backward_planning', 'risk_analysis', etc.
    input_hash TEXT NOT NULL, -- Hash of input data for cache validation
    result_data TEXT NOT NULL, -- JSON result
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER NOT NULL
);

-- Indexes for performance
CREATE INDEX idx_outcomes_org ON business_outcomes(organization_id);
CREATE INDEX idx_outcomes_creator ON business_outcomes(created_by);
CREATE INDEX idx_outcomes_status ON business_outcomes(status);
CREATE INDEX idx_activities_outcome ON outcome_activities(business_outcome_id);
CREATE INDEX idx_milestones_outcome ON outcome_milestones(business_outcome_id);
CREATE INDEX idx_risks_outcome ON outcome_risks(business_outcome_id);
CREATE INDEX idx_ai_cache_key ON ai_analysis_cache(cache_key);
CREATE INDEX idx_ai_cache_expires ON ai_analysis_cache(expires_at);

-- Sample data will be inserted after user registration
-- No sample data in schema to avoid foreign key constraint issues