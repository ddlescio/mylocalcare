-- Accessi autenticati giornalieri, minimizzati e conservati per 30 giorni.
-- Non vengono memorizzati IP, user agent, pagine visitate o utenti anonimi.

BEGIN;

CREATE TABLE IF NOT EXISTS accessi_utenti_giornalieri (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    giorno DATE NOT NULL,
    zona TEXT NOT NULL DEFAULT 'Zona non indicata',
    primo_accesso_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultimo_accesso_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (utente_id, giorno)
);

CREATE INDEX IF NOT EXISTS idx_accessi_utenti_giorno
    ON accessi_utenti_giornalieri (giorno DESC);

CREATE INDEX IF NOT EXISTS idx_accessi_utenti_zona_giorno
    ON accessi_utenti_giornalieri (zona, giorno DESC);

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE accessi_utenti_giornalieri
            TO localcare_app;

        GRANT USAGE, SELECT
            ON SEQUENCE accessi_utenti_giornalieri_id_seq
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica post-migrazione:
-- SELECT to_regclass('public.accessi_utenti_giornalieri');
