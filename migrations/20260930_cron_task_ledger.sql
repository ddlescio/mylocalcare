-- Registro persistente del cron consolidato.
--
-- Il vincolo (task_key, scheduled_for) rende ogni scadenza eseguibile una
-- sola volta. Un claim rimasto orfano puo essere ripreso solo dopo la scadenza
-- della lease; un errore esplicito puo essere riprovato dopo next_retry_at.

BEGIN;

CREATE TABLE IF NOT EXISTS cron_task_ledger (
    task_key TEXT NOT NULL,
    scheduled_for TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    claim_token UUID,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    claimed_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    last_error TEXT,
    result_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (task_key, scheduled_for)
);

CREATE INDEX IF NOT EXISTS idx_cron_task_ledger_retry
    ON cron_task_ledger (status, next_retry_at, lease_expires_at);

CREATE INDEX IF NOT EXISTS idx_cron_task_ledger_recent
    ON cron_task_ledger (scheduled_for DESC, task_key);

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE cron_task_ledger
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica post-migrazione:
-- SELECT to_regclass('public.cron_task_ledger');
