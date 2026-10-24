-- GuardRail PostgreSQL Run Ledger Schema & Idempotent Seed Data
-- Automatically executed on PostgreSQL container first boot via /docker-entrypoint-initdb.d

-- 1. Runs table
CREATE TABLE IF NOT EXISTS runs (
    run_id VARCHAR(64) PRIMARY KEY,
    sandbox_name VARCHAR(64) UNIQUE,
    problem_id VARCHAR(64) NOT NULL DEFAULT 'prompt_injection_exfil',
    defense_profile VARCHAR(32) NOT NULL DEFAULT 'baseline',
    state VARCHAR(32) NOT NULL DEFAULT 'created',
    execution_target VARCHAR(32) NOT NULL DEFAULT 'celesto_sandbox',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    success BOOLEAN,
    wall_clock_s DOUBLE PRECISION,
    boot_to_ready_s DOUBLE PRECISION,
    cost_usd DOUBLE PRECISION,
    attack_success BOOLEAN,
    evidence_path TEXT,
    run_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Events table
CREATE TABLE IF NOT EXISTS events (
    event_id VARCHAR(64) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Command Attempts table
CREATE TABLE IF NOT EXISTS command_attempts (
    attempt_id VARCHAR(64) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    command TEXT NOT NULL,
    decision VARCHAR(16) NOT NULL,
    reason TEXT,
    risk_level VARCHAR(16),
    execution_target VARCHAR(32) NOT NULL DEFAULT 'celesto_sandbox',
    canary_detected BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Policy Decisions table
CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id VARCHAR(64) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    attempt_id VARCHAR(64) REFERENCES command_attempts(attempt_id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    policy_name VARCHAR(64) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    risk_level VARCHAR(16),
    reason TEXT,
    decision_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Evaluations table
CREATE TABLE IF NOT EXISTS evaluations (
    evaluation_id VARCHAR(64) PRIMARY KEY,
    task TEXT NOT NULL,
    source_url TEXT NOT NULL,
    defense_profile VARCHAR(32) NOT NULL,
    run_count INTEGER NOT NULL DEFAULT 20,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    result_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_runs_sandbox_name ON runs(sandbox_name);
CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_cmd_run_id ON command_attempts(run_id);
CREATE INDEX IF NOT EXISTS idx_policy_run_id ON policy_decisions(run_id);
CREATE INDEX IF NOT EXISTS idx_eval_status ON evaluations(status);

-- Seed required demo row idempotently
-- Sandbox name matches 'sbx-seeddemo1', state is 'deleted', execution_target is strictly 'celesto_sandbox'
INSERT INTO runs (
    run_id,
    sandbox_name,
    problem_id,
    defense_profile,
    state,
    execution_target,
    success,
    wall_clock_s,
    boot_to_ready_s,
    cost_usd,
    attack_success,
    run_metadata,
    created_at,
    updated_at
) VALUES (
    'run_seeddemo1',
    'sbx-seeddemo1',
    'prompt_injection_exfil',
    'baseline',
    'deleted',
    'celesto_sandbox',
    TRUE,
    18.5,
    0.52,
    0.015,
    FALSE,
    '{"seeded": true, "note": "Illustrative infrastructure demo data, not real Celesto execution"}'::jsonb,
    NOW(),
    NOW()
) ON CONFLICT (run_id) DO NOTHING;
