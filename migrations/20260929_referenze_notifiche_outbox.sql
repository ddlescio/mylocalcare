-- Outbox persistente per notifiche owner/admin dopo la risposta referenza.
-- Idempotente: puo' essere rieseguita durante un rollout interrotto.

BEGIN;

CREATE TABLE IF NOT EXISTS referenze_notifiche_outbox (
    id BIGSERIAL PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE,
    referenza_id BIGINT NOT NULL
        REFERENCES referenze(id) ON DELETE CASCADE,
    destinatario_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    destinatario_tipo TEXT NOT NULL CHECK (
        destinatario_tipo IN ('owner', 'admin')
    ),
    titolo TEXT NOT NULL,
    messaggio TEXT NOT NULL,
    tipo_notifica TEXT NOT NULL,
    link TEXT,
    push_richiesta BOOLEAN NOT NULL DEFAULT FALSE,
    notifica_creata_at TIMESTAMPTZ,
    tentativi INTEGER NOT NULL DEFAULT 0 CHECK (tentativi >= 0),
    disponibile_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    bloccata_at TIMESTAMPTZ,
    blocco_token TEXT,
    elaborata_at TIMESTAMPTZ,
    ultimo_errore TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (bloccata_at IS NULL AND blocco_token IS NULL)
        OR (bloccata_at IS NOT NULL AND blocco_token IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_referenze_outbox_event_key
    ON referenze_notifiche_outbox (event_key);

CREATE INDEX IF NOT EXISTS idx_referenze_outbox_pending
    ON referenze_notifiche_outbox (
        elaborata_at, disponibile_at, bloccata_at, id
    );

CREATE INDEX IF NOT EXISTS idx_referenze_outbox_destinatario
    ON referenze_notifiche_outbox (destinatario_id, created_at DESC);

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE referenze_notifiche_outbox
            TO localcare_app;
        GRANT USAGE, SELECT
            ON SEQUENCE referenze_notifiche_outbox_id_seq
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi outbox non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;
