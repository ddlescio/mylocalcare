-- Disponibilita differenziate per categoria di servizio.
-- Migrazione esclusivamente additiva: l'agenda esistente in
-- disponibilita_profili resta valida come disponibilita generale.

BEGIN;

CREATE TABLE IF NOT EXISTS disponibilita_profili_categoria (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    categoria_slug TEXT NOT NULL CHECK (categoria_slug IN (
        'operatori-benessere', 'aiuto-in-casa', 'ripetizioni', 'babysitter',
        'pet-sitter', 'caregiver', 'escursioni-sport',
        'biglietti-spettacoli', 'libri-scuola', 'caffe-parole',
        'family-kids', 'eventi-socialita', 'spazi-sale'
    )),
    stato_generale TEXT NOT NULL DEFAULT 'disponibile' CHECK (
        stato_generale IN ('disponibile', 'limitata', 'non_disponibile')
    ),
    a_chiamata BOOLEAN NOT NULL DEFAULT FALSE,
    fuso_orario TEXT NOT NULL DEFAULT 'Europe/Rome',
    confermata_at TIMESTAMPTZ,
    ultimo_promemoria_at TIMESTAMPTZ,
    versione INTEGER NOT NULL DEFAULT 1 CHECK (versione >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (utente_id, categoria_slug)
);

CREATE TABLE IF NOT EXISTS disponibilita_settimanale_categoria (
    id BIGSERIAL PRIMARY KEY,
    profilo_categoria_id BIGINT NOT NULL
        REFERENCES disponibilita_profili_categoria(id) ON DELETE CASCADE,
    giorno_settimana INTEGER NOT NULL CHECK (giorno_settimana BETWEEN 1 AND 7),
    fascia TEXT NOT NULL CHECK (
        fascia IN ('mattina', 'pomeriggio', 'sera', 'notte')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (profilo_categoria_id, giorno_settimana, fascia)
);

CREATE TABLE IF NOT EXISTS disponibilita_date_speciali_categoria (
    id BIGSERIAL PRIMARY KEY,
    profilo_categoria_id BIGINT NOT NULL
        REFERENCES disponibilita_profili_categoria(id) ON DELETE CASCADE,
    data DATE NOT NULL,
    tipo TEXT NOT NULL CHECK (tipo IN ('disponibile', 'non_disponibile')),
    fasce TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (profilo_categoria_id, data)
);

CREATE TABLE IF NOT EXISTS disponibilita_assenze_categoria (
    id BIGSERIAL PRIMARY KEY,
    profilo_categoria_id BIGINT NOT NULL
        REFERENCES disponibilita_profili_categoria(id) ON DELETE CASCADE,
    data_inizio DATE NOT NULL,
    data_fine DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (profilo_categoria_id, data_inizio, data_fine),
    CHECK (data_fine >= data_inizio)
);

CREATE INDEX IF NOT EXISTS idx_disponibilita_profili_categoria_utente
    ON disponibilita_profili_categoria (utente_id, categoria_slug);

CREATE INDEX IF NOT EXISTS idx_disponibilita_categoria_confermata
    ON disponibilita_profili_categoria (confermata_at, stato_generale);

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE
                disponibilita_profili_categoria,
                disponibilita_settimanale_categoria,
                disponibilita_date_speciali_categoria,
                disponibilita_assenze_categoria
            TO localcare_app;

        GRANT USAGE, SELECT
            ON SEQUENCE
                disponibilita_profili_categoria_id_seq,
                disponibilita_settimanale_categoria_id_seq,
                disponibilita_date_speciali_categoria_id_seq,
                disponibilita_assenze_categoria_id_seq
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT to_regclass('public.disponibilita_profili_categoria'),
--        to_regclass('public.disponibilita_settimanale_categoria'),
--        to_regclass('public.disponibilita_date_speciali_categoria'),
--        to_regclass('public.disponibilita_assenze_categoria');
