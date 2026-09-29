-- Statistiche giornaliere di prima parte, minimizzate e conservate 30 giorni.
-- Non vengono memorizzati IP, user agent, pagine visitate o identificatori
-- dei visitatori anonimi. Per questi ultimi resta solo un contatore aggregato.

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

CREATE TABLE IF NOT EXISTS accessi_anonimi_giornalieri (
    giorno DATE PRIMARY KEY,
    visite_sessione INTEGER NOT NULL DEFAULT 0
        CHECK (visite_sessione >= 0),
    primo_accesso_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultimo_accesso_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE accessi_utenti_giornalieri,
                     accessi_anonimi_giornalieri
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
-- SELECT to_regclass('public.accessi_anonimi_giornalieri');
