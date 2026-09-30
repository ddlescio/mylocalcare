-- Ciclo di riconferma degli annunci offro e rollout iniziale.
-- L'archiviazione e reversibile: contenuti, foto e servizi non vengono
-- cancellati. Un acquisto reale riconferma la disponibilita e riavvia il
-- normale ciclo 25/30/37/44, senza eccezioni legate alla durata del servizio.

BEGIN;

CREATE TABLE IF NOT EXISTS annunci_disponibilita_ciclo (
    annuncio_id INTEGER PRIMARY KEY
        REFERENCES annunci(id) ON DELETE CASCADE,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    origine TEXT NOT NULL CHECK (origine IN ('ordinario', 'rollout')),
    stato TEXT NOT NULL DEFAULT 'attivo' CHECK (stato IN (
        'attivo',
        'non_disponibile_scadenza',
        'archiviato',
        'completato'
    )),
    ciclo_versione INTEGER NOT NULL DEFAULT 1 CHECK (ciclo_versione >= 1),
    ciclo_iniziato_at TIMESTAMPTZ NOT NULL,
    confermata_at_snapshot TIMESTAMPTZ,
    non_disponibile_at TIMESTAMPTZ,
    archiviazione_prevista_at TIMESTAMPTZ,
    archiviato_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS annunci_disponibilita_eventi (
    id BIGSERIAL PRIMARY KEY,
    annuncio_id INTEGER NOT NULL
        REFERENCES annunci(id) ON DELETE CASCADE,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    ciclo_versione INTEGER NOT NULL CHECK (ciclo_versione >= 1),
    codice TEXT NOT NULL,
    notifica_interna_at TIMESTAMPTZ,
    push_inviata_at TIMESTAMPTZ,
    email_inviata_at TIMESTAMPTZ,
    push_tentativi INTEGER NOT NULL DEFAULT 0 CHECK (push_tentativi >= 0),
    email_tentativi INTEGER NOT NULL DEFAULT 0 CHECK (email_tentativi >= 0),
    ultimo_errore TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (annuncio_id, ciclo_versione, codice)
);

CREATE INDEX IF NOT EXISTS idx_annunci_disponibilita_ciclo_stato_scadenza
    ON annunci_disponibilita_ciclo (
        stato, archiviazione_prevista_at, ciclo_iniziato_at
    );

CREATE INDEX IF NOT EXISTS idx_annunci_disponibilita_ciclo_utente
    ON annunci_disponibilita_ciclo (utente_id, stato);

CREATE INDEX IF NOT EXISTS idx_annunci_disponibilita_eventi_pendenti
    ON annunci_disponibilita_eventi (
        notifica_interna_at, push_inviata_at, email_inviata_at, created_at
    );

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE
                annunci_disponibilita_ciclo,
                annunci_disponibilita_eventi
            TO localcare_app;

        GRANT USAGE, SELECT
            ON SEQUENCE annunci_disponibilita_eventi_id_seq
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica post-migrazione:
-- SELECT to_regclass('public.annunci_disponibilita_ciclo'),
--        to_regclass('public.annunci_disponibilita_eventi');
