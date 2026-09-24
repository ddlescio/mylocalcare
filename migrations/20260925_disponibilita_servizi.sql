-- Disponibilità strutturata, unica per il profilo utente.
-- Non modifica né interpreta il campo storico utenti.orari, che resta una
-- preferenza di contatto separata.
-- Eseguire su PostgreSQL prima del deploy del codice applicativo.

BEGIN;

CREATE TABLE IF NOT EXISTS disponibilita_profili (
    utente_id INTEGER PRIMARY KEY
        REFERENCES utenti(id) ON DELETE CASCADE,
    stato_generale TEXT NOT NULL DEFAULT 'disponibile' CHECK (
        stato_generale IN ('disponibile', 'limitata', 'non_disponibile')
    ),
    fuso_orario TEXT NOT NULL DEFAULT 'Europe/Rome',
    confermata_at TIMESTAMPTZ,
    ultimo_promemoria_at TIMESTAMPTZ,
    versione INTEGER NOT NULL DEFAULT 1 CHECK (versione >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS disponibilita_settimanale (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    giorno_settimana INTEGER NOT NULL CHECK (giorno_settimana BETWEEN 1 AND 7),
    fascia TEXT NOT NULL CHECK (
        fascia IN ('mattina', 'pomeriggio', 'sera', 'notte')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (utente_id, giorno_settimana, fascia)
);

CREATE TABLE IF NOT EXISTS disponibilita_date_speciali (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    data DATE NOT NULL,
    tipo TEXT NOT NULL CHECK (tipo IN ('disponibile', 'non_disponibile')),
    fasce TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS disponibilita_assenze (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    data_inizio DATE NOT NULL,
    data_fine DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (data_fine >= data_inizio)
);

CREATE INDEX IF NOT EXISTS idx_disponibilita_profili_stato
    ON disponibilita_profili (stato_generale, confermata_at);

CREATE INDEX IF NOT EXISTS idx_disponibilita_profili_promemoria
    ON disponibilita_profili (ultimo_promemoria_at, confermata_at);

CREATE INDEX IF NOT EXISTS idx_disponibilita_settimanale_utente
    ON disponibilita_settimanale (utente_id, giorno_settimana);

CREATE INDEX IF NOT EXISTS idx_disponibilita_date_utente
    ON disponibilita_date_speciali (utente_id, data);

CREATE UNIQUE INDEX IF NOT EXISTS ux_disponibilita_date_utente
    ON disponibilita_date_speciali (utente_id, data);

CREATE INDEX IF NOT EXISTS idx_disponibilita_assenze_utente
    ON disponibilita_assenze (utente_id, data_inizio, data_fine);

CREATE UNIQUE INDEX IF NOT EXISTS ux_disponibilita_assenze_utente
    ON disponibilita_assenze (utente_id, data_inizio, data_fine);

-- L'applicazione di produzione usa un ruolo separato. Il blocco resta
-- ripetibile e non fallisce negli ambienti in cui quel ruolo non esiste.
DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE
                disponibilita_profili,
                disponibilita_settimanale,
                disponibilita_date_speciali,
                disponibilita_assenze
            TO localcare_app;

        IF to_regclass('public.disponibilita_settimanale_id_seq') IS NOT NULL THEN
            GRANT USAGE, SELECT
                ON SEQUENCE disponibilita_settimanale_id_seq
                TO localcare_app;
        END IF;

        IF to_regclass('public.disponibilita_date_speciali_id_seq') IS NOT NULL THEN
            GRANT USAGE, SELECT
                ON SEQUENCE disponibilita_date_speciali_id_seq
                TO localcare_app;
        END IF;

        IF to_regclass('public.disponibilita_assenze_id_seq') IS NOT NULL THEN
            GRANT USAGE, SELECT
                ON SEQUENCE disponibilita_assenze_id_seq
                TO localcare_app;
        END IF;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT to_regclass('public.disponibilita_profili'),
--        to_regclass('public.disponibilita_settimanale'),
--        to_regclass('public.disponibilita_date_speciali'),
--        to_regclass('public.disponibilita_assenze');
