-- Outbox retry-safe per i promemoria ordinari di disponibilita 25/30/37.
-- Ogni canale viene marcato soltanto dopo una consegna riuscita, cosi un
-- guasto temporaneo non fa perdere email o push e non duplica gli altri.

BEGIN;

CREATE TABLE IF NOT EXISTS disponibilita_promemoria_eventi (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    fase TEXT NOT NULL CHECK (
        fase IN ('in_scadenza', 'scaduta', 'ultimo_avviso')
    ),
    titolo_sorgente TEXT NOT NULL,
    messaggio_sorgente TEXT NOT NULL,
    link TEXT NOT NULL,
    notifica_interna_at TIMESTAMPTZ,
    push_inviata_at TIMESTAMPTZ,
    email_inviata_at TIMESTAMPTZ,
    notifica_tentativi INTEGER NOT NULL DEFAULT 0
        CHECK (notifica_tentativi >= 0),
    push_tentativi INTEGER NOT NULL DEFAULT 0
        CHECK (push_tentativi >= 0),
    email_tentativi INTEGER NOT NULL DEFAULT 0
        CHECK (email_tentativi >= 0),
    ultimo_errore TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_disponibilita_promemoria_eventi_pendenti
    ON disponibilita_promemoria_eventi (
        notifica_interna_at, push_inviata_at,
        email_inviata_at, created_at
    );

CREATE INDEX IF NOT EXISTS idx_disponibilita_promemoria_eventi_utente
    ON disponibilita_promemoria_eventi (utente_id, created_at DESC);

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE disponibilita_promemoria_eventi
            TO localcare_app;

        GRANT USAGE, SELECT
            ON SEQUENCE disponibilita_promemoria_eventi_id_seq
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica:
-- SELECT to_regclass('public.disponibilita_promemoria_eventi');
