-- Migrazione PostgreSQL "Mi interessa"
-- Ordine sicuro: eseguire questo file prima di distribuire il codice applicativo.

BEGIN;

CREATE TABLE IF NOT EXISTS interessi_annunci (
    id BIGSERIAL PRIMARY KEY,
    annuncio_id INTEGER NOT NULL
        REFERENCES annunci(id) ON DELETE CASCADE,
    utente_interessato_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    attivo BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disattivato_at TIMESTAMPTZ,
    ultima_notifica_at TIMESTAMPTZ,
    chat_opened_at TIMESTAMPTZ,
    CONSTRAINT uq_interessi_annunci_annuncio_utente
        UNIQUE (annuncio_id, utente_interessato_id)
);

CREATE INDEX IF NOT EXISTS idx_interessi_annunci_annuncio_attivo_data
    ON interessi_annunci (annuncio_id, attivo, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_interessi_annunci_utente_attivo
    ON interessi_annunci (utente_interessato_id, attivo);

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT column_name, data_type, is_nullable
-- FROM information_schema.columns
-- WHERE table_name = 'interessi_annunci'
-- ORDER BY ordinal_position;
