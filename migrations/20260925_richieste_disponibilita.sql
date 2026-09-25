-- Base relazionale per "Chiedi disponibilita".
-- La richiesta e sempre legata a un annuncio "offro"; la verifica che
-- offerente_id sia il proprietario di quell'annuncio viene eseguita dal
-- futuro endpoint nella stessa transazione dell'inserimento.

BEGIN;

CREATE TABLE IF NOT EXISTS richieste_disponibilita (
    id BIGSERIAL PRIMARY KEY,
    annuncio_id INTEGER NOT NULL
        REFERENCES annunci(id) ON DELETE CASCADE,
    richiedente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    offerente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    a_chiamata BOOLEAN NOT NULL DEFAULT FALSE,
    stato TEXT NOT NULL DEFAULT 'in_attesa' CHECK (
        stato IN (
            'in_attesa',
            'disponibile',
            'non_disponibile',
            'informazioni',
            'scaduta'
        )
    ),
    risposta_at TIMESTAMPTZ,
    versione INTEGER NOT NULL DEFAULT 1 CHECK (versione >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (richiedente_id <> offerente_id),
    CHECK (
        (stato = 'in_attesa' AND risposta_at IS NULL)
        OR
        (stato <> 'in_attesa' AND risposta_at IS NOT NULL)
    )
);

-- Mantiene la migrazione idempotente anche se la tabella era stata creata
-- prima dell'introduzione dell'opzione indipendente "A chiamata".
ALTER TABLE richieste_disponibilita
    ADD COLUMN IF NOT EXISTS a_chiamata BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS richieste_disponibilita_fasce (
    id BIGSERIAL PRIMARY KEY,
    richiesta_id BIGINT NOT NULL
        REFERENCES richieste_disponibilita(id) ON DELETE CASCADE,
    giorno_settimana INTEGER NOT NULL CHECK (
        giorno_settimana BETWEEN 1 AND 7
    ),
    fascia TEXT NOT NULL CHECK (
        fascia IN ('mattina', 'pomeriggio', 'sera', 'notte')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (richiesta_id, giorno_settimana, fascia)
);

CREATE TABLE IF NOT EXISTS richieste_disponibilita_intervalli (
    id BIGSERIAL PRIMARY KEY,
    richiesta_id BIGINT NOT NULL
        REFERENCES richieste_disponibilita(id) ON DELETE CASCADE,
    giorno_settimana INTEGER NOT NULL CHECK (
        giorno_settimana BETWEEN 1 AND 7
    ),
    ora_inizio TIME WITHOUT TIME ZONE NOT NULL,
    ora_fine TIME WITHOUT TIME ZONE NOT NULL,
    giorno_successivo BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (
        richiesta_id,
        giorno_settimana,
        ora_inizio,
        ora_fine,
        giorno_successivo
    ),
    CHECK (
        (
            giorno_successivo = FALSE
            AND ora_fine > ora_inizio
        )
        OR
        (
            giorno_successivo = TRUE
            AND ora_inizio > ora_fine
            AND ora_inizio >= TIME '18:00'
            AND ora_fine <= TIME '08:00'
        )
    )
);

-- Una persona non puo accumulare due richieste contemporaneamente aperte
-- sullo stesso annuncio. Gli altri limiti temporali restano applicativi.
CREATE UNIQUE INDEX IF NOT EXISTS ux_richieste_disponibilita_pendente
    ON richieste_disponibilita (annuncio_id, richiedente_id)
    WHERE stato = 'in_attesa';

CREATE INDEX IF NOT EXISTS idx_richieste_disponibilita_offerente
    ON richieste_disponibilita (offerente_id, stato, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_richieste_disponibilita_richiedente
    ON richieste_disponibilita (richiedente_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_richieste_disponibilita_annuncio
    ON richieste_disponibilita (annuncio_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_richieste_disponibilita_fasce_richiesta
    ON richieste_disponibilita_fasce (
        richiesta_id,
        giorno_settimana,
        fascia
    );

CREATE INDEX IF NOT EXISTS idx_richieste_disponibilita_intervalli_richiesta
    ON richieste_disponibilita_intervalli (
        richiesta_id,
        giorno_settimana,
        ora_inizio
    );

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE
                richieste_disponibilita,
                richieste_disponibilita_fasce,
                richieste_disponibilita_intervalli
            TO localcare_app;

        GRANT USAGE, SELECT
            ON SEQUENCE
                richieste_disponibilita_id_seq,
                richieste_disponibilita_fasce_id_seq,
                richieste_disponibilita_intervalli_id_seq
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT to_regclass('public.richieste_disponibilita'),
--        to_regclass('public.richieste_disponibilita_fasce'),
--        to_regclass('public.richieste_disponibilita_intervalli');
