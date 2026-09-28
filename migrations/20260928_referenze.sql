-- Referenze professionali con contatti cifrati, consenso separato e audit.
-- Non collega automaticamente una referenza a una scheda esperienza.
-- Eseguire su PostgreSQL prima del deploy del codice applicativo.

BEGIN;

CREATE TABLE IF NOT EXISTS referenze (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    categoria_slug TEXT NOT NULL,
    tipo_rapporto TEXT NOT NULL CHECK (
        tipo_rapporto IN (
            'famiglia', 'datore_lavoro', 'cliente', 'struttura', 'altro'
        )
    ),
    anno_inizio SMALLINT,
    anno_fine SMALLINT,
    durata_fascia TEXT CHECK (
        durata_fascia IS NULL OR durata_fascia IN (
            'meno_3_mesi', '3_6_mesi', '6_12_mesi',
            '1_2_anni', 'oltre_2_anni'
        )
    ),
    esperienza_diretta BOOLEAN NOT NULL DEFAULT FALSE,
    testo_referente TEXT,
    stato_risposta TEXT NOT NULL DEFAULT 'in_attesa' CHECK (
        stato_risposta IN (
            'in_attesa', 'risposta_ricevuta', 'rifiutata',
            'scaduta', 'revocata', 'cancellata'
        )
    ),
    stato_verifica TEXT NOT NULL DEFAULT 'non_esaminata' CHECK (
        stato_verifica IN (
            'non_esaminata', 'in_coda', 'verificata',
            'non_confermata', 'non_verificabile', 'revocata'
        )
    ),
    autorizza_pubblicazione BOOLEAN NOT NULL DEFAULT FALSE,
    autorizza_testo_pubblico BOOLEAN NOT NULL DEFAULT FALSE,
    autorizza_contatto_verifica BOOLEAN NOT NULL DEFAULT FALSE,
    pubblicazione_approvata_admin BOOLEAN NOT NULL DEFAULT FALSE,
    pubblicazione_approvata_at TIMESTAMPTZ,
    pubblicazione_approvata_da_admin_id INTEGER
        REFERENCES utenti(id) ON DELETE SET NULL,
    visibile_profilo BOOLEAN NOT NULL DEFAULT TRUE,
    consenso_versione TEXT,
    consenso_trattamento_at TIMESTAMPTZ,
    autorizzazione_pubblica_at TIMESTAMPTZ,
    autorizzazione_testo_at TIMESTAMPTZ,
    autorizzazione_contatto_at TIMESTAMPTZ,
    risposta_at TIMESTAMPTZ,
    verificata_at TIMESTAMPTZ,
    revocata_at TIMESTAMPTZ,
    cancellata_at TIMESTAMPTZ,
    verificata_da_admin_id INTEGER
        REFERENCES utenti(id) ON DELETE SET NULL,
    -- email/altro sono valori storici; le nuove verifiche applicative
    -- consentono come ricontatto soltanto il telefono autorizzato.
    metodo_verifica TEXT NOT NULL DEFAULT 'nessuno' CHECK (
        metodo_verifica IN ('nessuno', 'email', 'telefono', 'altro')
    ),
    nota_admin TEXT,
    nota_pubblica TEXT,
    versione INTEGER NOT NULL DEFAULT 1 CHECK (versione >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (TRIM(categoria_slug) <> ''),
    CHECK (anno_inizio IS NULL OR anno_inizio BETWEEN 1900 AND 2200),
    CHECK (anno_fine IS NULL OR anno_fine BETWEEN 1900 AND 2200),
    CHECK (
        anno_fine IS NULL OR anno_inizio IS NULL OR anno_fine >= anno_inizio
    ),
    CHECK (
        stato_risposta <> 'risposta_ricevuta' OR risposta_at IS NOT NULL
    ),
    CHECK (
        stato_verifica <> 'verificata'
        OR (verificata_at IS NOT NULL AND stato_risposta = 'risposta_ricevuta')
    ),
    CHECK (
        autorizza_pubblicazione = FALSE
        OR (
            stato_risposta = 'risposta_ricevuta'
            AND consenso_trattamento_at IS NOT NULL
            AND autorizzazione_pubblica_at IS NOT NULL
        )
    ),
    CHECK (
        autorizza_testo_pubblico = FALSE
        OR (
            autorizza_pubblicazione = TRUE
            AND testo_referente IS NOT NULL
            AND TRIM(testo_referente) <> ''
            AND autorizzazione_testo_at IS NOT NULL
        )
    ),
    CHECK (
        pubblicazione_approvata_admin = FALSE
        OR (
            stato_risposta = 'risposta_ricevuta'
            AND autorizza_pubblicazione = TRUE
            AND stato_verifica NOT IN ('non_confermata', 'revocata')
            AND pubblicazione_approvata_at IS NOT NULL
            AND pubblicazione_approvata_da_admin_id IS NOT NULL
        )
    ),
    CHECK (revocata_at IS NULL OR stato_risposta = 'revocata'),
    CHECK (cancellata_at IS NULL OR stato_risposta = 'cancellata')
);

-- Mantiene la migrazione idempotente anche se una prima versione della
-- tabella e stata gia creata durante il rollout.
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS autorizza_contatto_verifica BOOLEAN
    NOT NULL DEFAULT FALSE;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS autorizzazione_contatto_at TIMESTAMPTZ;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS pubblicazione_approvata_admin BOOLEAN
    NOT NULL DEFAULT FALSE;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS pubblicazione_approvata_at TIMESTAMPTZ;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS pubblicazione_approvata_da_admin_id INTEGER
    REFERENCES utenti(id) ON DELETE SET NULL;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS visibile_profilo BOOLEAN
    NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS referenze_contatti (
    id BIGSERIAL PRIMARY KEY,
    referenza_id BIGINT NOT NULL UNIQUE
        REFERENCES referenze(id) ON DELETE CASCADE,
    email_cifrata TEXT,
    email_nonce TEXT,
    email_tag TEXT,
    email_key_id TEXT,
    email_hash TEXT,
    nome_cifrato TEXT,
    nome_nonce TEXT,
    nome_tag TEXT,
    telefono_cifrato TEXT,
    telefono_nonce TEXT,
    telefono_tag TEXT,
    messaggio_invito_cifrato TEXT,
    messaggio_invito_nonce TEXT,
    messaggio_invito_tag TEXT,
    token_hash TEXT UNIQUE,
    token_expires_at TIMESTAMPTZ,
    token_consumed_at TIMESTAMPTZ,
    ultimo_invio_at TIMESTAMPTZ,
    numero_invii INTEGER NOT NULL DEFAULT 0 CHECK (numero_invii >= 0),
    aperto_at TIMESTAMPTZ,
    ultimo_errore_invio TEXT,
    contatto_purge_at TIMESTAMPTZ,
    contatto_purged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (
            email_cifrata IS NOT NULL AND email_nonce IS NOT NULL
            AND email_tag IS NOT NULL AND email_key_id IS NOT NULL
            AND email_hash IS NOT NULL
        )
        OR
        (
            email_cifrata IS NULL AND email_nonce IS NULL
            AND email_tag IS NULL AND email_key_id IS NULL
            AND email_hash IS NULL
        )
    ),
    CHECK (
        (nome_cifrato IS NOT NULL AND nome_nonce IS NOT NULL AND nome_tag IS NOT NULL)
        OR
        (nome_cifrato IS NULL AND nome_nonce IS NULL AND nome_tag IS NULL)
    ),
    CHECK (
        (
            telefono_cifrato IS NOT NULL
            AND telefono_nonce IS NOT NULL
            AND telefono_tag IS NOT NULL
        )
        OR
        (
            telefono_cifrato IS NULL
            AND telefono_nonce IS NULL
            AND telefono_tag IS NULL
        )
    ),
    CHECK (
        (
            messaggio_invito_cifrato IS NOT NULL
            AND messaggio_invito_nonce IS NOT NULL
            AND messaggio_invito_tag IS NOT NULL
        )
        OR
        (
            messaggio_invito_cifrato IS NULL
            AND messaggio_invito_nonce IS NULL
            AND messaggio_invito_tag IS NULL
        )
    ),
    CHECK (
        (token_hash IS NOT NULL AND token_expires_at IS NOT NULL)
        OR (token_hash IS NULL AND token_expires_at IS NULL)
    )
);

-- Compatibilita con eventuali installazioni create durante le prime fasi del
-- rollout, prima dell'introduzione dello stato di invio e della retention.
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS ultimo_errore_invio TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS contatto_purge_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS contatto_purged_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS telefono_cifrato TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS telefono_nonce TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS telefono_tag TEXT;

CREATE TABLE IF NOT EXISTS referenze_eventi (
    id BIGSERIAL PRIMARY KEY,
    referenza_id BIGINT NOT NULL
        REFERENCES referenze(id) ON DELETE CASCADE,
    tipo_evento TEXT NOT NULL,
    attore_tipo TEXT NOT NULL CHECK (
        attore_tipo IN ('utente', 'referente', 'admin', 'sistema')
    ),
    attore_utente_id INTEGER
        REFERENCES utenti(id) ON DELETE SET NULL,
    dettagli_snapshot TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (TRIM(tipo_evento) <> '')
);

CREATE INDEX IF NOT EXISTS idx_referenze_utente
    ON referenze (utente_id, stato_risposta, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_referenze_coda_admin
    ON referenze (stato_verifica, risposta_at DESC);

CREATE INDEX IF NOT EXISTS idx_referenze_pubbliche
    ON referenze (
        utente_id, autorizza_pubblicazione,
        pubblicazione_approvata_admin, visibile_profilo,
        stato_risposta, created_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_referenze_contatti_email_hash
    ON referenze_contatti (email_hash);

CREATE INDEX IF NOT EXISTS idx_referenze_contatti_scadenza
    ON referenze_contatti (token_expires_at, token_consumed_at);

CREATE INDEX IF NOT EXISTS idx_referenze_contatti_purge
    ON referenze_contatti (contatto_purge_at, contatto_purged_at);

CREATE INDEX IF NOT EXISTS idx_referenze_eventi_storico
    ON referenze_eventi (referenza_id, created_at DESC);

DO $grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'localcare_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON TABLE referenze, referenze_contatti, referenze_eventi
            TO localcare_app;

        GRANT USAGE, SELECT
            ON SEQUENCE
                referenze_id_seq,
                referenze_contatti_id_seq,
                referenze_eventi_id_seq
            TO localcare_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT to_regclass('public.referenze'),
--        to_regclass('public.referenze_contatti'),
--        to_regclass('public.referenze_eventi');
