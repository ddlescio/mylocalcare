-- Intervalli orari reali per la disponibilita settimanale.
-- Le fasce ampie esistenti restano indipendenti: nessuna conversione
-- automatica mattina/pomeriggio/sera/notte viene effettuata.

BEGIN;

CREATE TABLE IF NOT EXISTS disponibilita_intervalli (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    giorno_settimana INTEGER NOT NULL CHECK (giorno_settimana BETWEEN 1 AND 7),
    ora_inizio TIME WITHOUT TIME ZONE NOT NULL,
    ora_fine TIME WITHOUT TIME ZONE NOT NULL,
    giorno_successivo BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (
        utente_id, giorno_settimana, ora_inizio,
        ora_fine, giorno_successivo
    ),
    CHECK (
        (
            giorno_successivo = FALSE
            AND ora_fine > ora_inizio
        )
        OR (
            giorno_successivo = TRUE
            AND ora_inizio > ora_fine
            AND ora_inizio >= TIME '18:00'
            AND ora_fine <= TIME '08:00'
        )
    )
);

CREATE TABLE IF NOT EXISTS disponibilita_intervalli_categoria (
    id BIGSERIAL PRIMARY KEY,
    profilo_categoria_id BIGINT NOT NULL
        REFERENCES disponibilita_profili_categoria(id) ON DELETE CASCADE,
    giorno_settimana INTEGER NOT NULL CHECK (giorno_settimana BETWEEN 1 AND 7),
    ora_inizio TIME WITHOUT TIME ZONE NOT NULL,
    ora_fine TIME WITHOUT TIME ZONE NOT NULL,
    giorno_successivo BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (
        profilo_categoria_id, giorno_settimana, ora_inizio,
        ora_fine, giorno_successivo
    ),
    CHECK (
        (
            giorno_successivo = FALSE
            AND ora_fine > ora_inizio
        )
        OR (
            giorno_successivo = TRUE
            AND ora_inizio > ora_fine
            AND ora_inizio >= TIME '18:00'
            AND ora_fine <= TIME '08:00'
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_disponibilita_intervalli_utente_giorno
    ON disponibilita_intervalli (
        utente_id, giorno_settimana, ora_inizio, ora_fine
    );

CREATE INDEX IF NOT EXISTS idx_disponibilita_intervalli_categoria_giorno
    ON disponibilita_intervalli_categoria (
        profilo_categoria_id, giorno_settimana, ora_inizio, ora_fine
    );

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE
                disponibilita_intervalli,
                disponibilita_intervalli_categoria
            TO localcare_app;

        IF to_regclass('public.disponibilita_intervalli_id_seq') IS NOT NULL THEN
            GRANT USAGE, SELECT
                ON SEQUENCE disponibilita_intervalli_id_seq
                TO localcare_app;
        END IF;

        IF to_regclass(
            'public.disponibilita_intervalli_categoria_id_seq'
        ) IS NOT NULL THEN
            GRANT USAGE, SELECT
                ON SEQUENCE disponibilita_intervalli_categoria_id_seq
                TO localcare_app;
        END IF;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica:
-- SELECT to_regclass('public.disponibilita_intervalli'),
--        to_regclass('public.disponibilita_intervalli_categoria');
