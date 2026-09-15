-- Stato di verifica amministrativa delle segnalazioni chat.
-- Eseguire su PostgreSQL prima del deploy del codice applicativo.

BEGIN;

CREATE TABLE IF NOT EXISTS chat_risk_reviews (
    utente_id INTEGER PRIMARY KEY
        REFERENCES utenti(id) ON DELETE CASCADE,
    controllato_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    controllato_da_admin_id INTEGER
        REFERENCES utenti(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_risk_reviews_controllato_at
ON chat_risk_reviews (controllato_at DESC);

COMMIT;
