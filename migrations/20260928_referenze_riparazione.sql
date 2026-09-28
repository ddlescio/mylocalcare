-- Ripara installazioni in cui il rollout referenze si e fermato dopo la
-- creazione parziale delle tabelle. Idempotente su PostgreSQL.
-- Su un database esistente con tabelle referenze gia presenti, eseguire
-- direttamente questo file prima del deploy applicativo: la migrazione base
-- usa CREATE TABLE IF NOT EXISTS e potrebbe fermarsi sugli indici se lo
-- schema legacy e incompleto. Solo su un'installazione nuova eseguire prima
-- 20260928_referenze.sql e poi questo file.

BEGIN;

ALTER TABLE referenze ADD COLUMN IF NOT EXISTS anno_inizio INTEGER;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS anno_fine INTEGER;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS durata_fascia TEXT;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS esperienza_diretta BOOLEAN
    NOT NULL DEFAULT FALSE;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS testo_referente TEXT;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS stato_risposta TEXT
    NOT NULL DEFAULT 'in_attesa';
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS stato_verifica TEXT
    NOT NULL DEFAULT 'non_esaminata';
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS autorizza_pubblicazione BOOLEAN
    NOT NULL DEFAULT FALSE;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS autorizza_testo_pubblico BOOLEAN
    NOT NULL DEFAULT FALSE;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS autorizza_contatto_verifica BOOLEAN
    NOT NULL DEFAULT FALSE;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS pubblicazione_approvata_admin BOOLEAN
    NOT NULL DEFAULT FALSE;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS pubblicazione_approvata_at TIMESTAMPTZ;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS pubblicazione_approvata_da_admin_id INTEGER
    REFERENCES utenti(id) ON DELETE SET NULL;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS visibile_profilo BOOLEAN
    NOT NULL DEFAULT TRUE;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS consenso_versione TEXT;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS consenso_trattamento_at TIMESTAMPTZ;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS autorizzazione_pubblica_at TIMESTAMPTZ;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS autorizzazione_testo_at TIMESTAMPTZ;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS autorizzazione_contatto_at TIMESTAMPTZ;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS risposta_at TIMESTAMPTZ;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS verificata_at TIMESTAMPTZ;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS revocata_at TIMESTAMPTZ;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS cancellata_at TIMESTAMPTZ;
ALTER TABLE referenze
    ADD COLUMN IF NOT EXISTS verificata_da_admin_id INTEGER
    REFERENCES utenti(id) ON DELETE SET NULL;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS metodo_verifica TEXT
    NOT NULL DEFAULT 'nessuno';
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS nota_admin TEXT;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS nota_pubblica TEXT;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS versione INTEGER
    NOT NULL DEFAULT 1;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
    NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE referenze ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
    NOT NULL DEFAULT CURRENT_TIMESTAMP;

UPDATE referenze
SET stato_risposta = COALESCE(stato_risposta, 'in_attesa'),
    stato_verifica = COALESCE(stato_verifica, 'non_esaminata'),
    esperienza_diretta = COALESCE(esperienza_diretta, FALSE),
    autorizza_pubblicazione = COALESCE(autorizza_pubblicazione, FALSE),
    autorizza_testo_pubblico = COALESCE(autorizza_testo_pubblico, FALSE),
    autorizza_contatto_verifica =
        COALESCE(autorizza_contatto_verifica, FALSE),
    pubblicazione_approvata_admin =
        COALESCE(pubblicazione_approvata_admin, FALSE),
    visibile_profilo = COALESCE(visibile_profilo, TRUE),
    metodo_verifica = COALESCE(metodo_verifica, 'nessuno'),
    versione = GREATEST(COALESCE(versione, 1), 1),
    created_at = COALESCE(created_at, CURRENT_TIMESTAMP),
    updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP);

DO $reference_state_repair$
DECLARE
    constraint_row RECORD;
BEGIN
    FOR constraint_row IN
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = 'public.referenze'::regclass
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ILIKE '%stato_risposta%'
          AND pg_get_constraintdef(con.oid) ILIKE '%in_attesa%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.referenze DROP CONSTRAINT %I',
            constraint_row.conname
        );
    END LOOP;

    FOR constraint_row IN
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = 'public.referenze'::regclass
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ILIKE '%stato_verifica%'
          AND pg_get_constraintdef(con.oid) ILIKE '%non_esaminata%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.referenze DROP CONSTRAINT %I',
            constraint_row.conname
        );
    END LOOP;

    FOR constraint_row IN
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = 'public.referenze'::regclass
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ILIKE '%metodo_verifica%'
          AND pg_get_constraintdef(con.oid) ILIKE '%nessuno%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.referenze DROP CONSTRAINT %I',
            constraint_row.conname
        );
    END LOOP;
END
$reference_state_repair$;

ALTER TABLE referenze
    ADD CONSTRAINT referenze_stato_risposta_check_v2 CHECK (
        stato_risposta IN (
            'in_attesa', 'risposta_ricevuta', 'rifiutata',
            'scaduta', 'revocata', 'cancellata'
        )
    ) NOT VALID;
ALTER TABLE referenze
    VALIDATE CONSTRAINT referenze_stato_risposta_check_v2;
ALTER TABLE referenze
    ADD CONSTRAINT referenze_stato_verifica_check_v2 CHECK (
        stato_verifica IN (
            'non_esaminata', 'in_coda', 'verificata',
            'non_confermata', 'non_verificabile', 'revocata'
        )
    ) NOT VALID;
ALTER TABLE referenze
    VALIDATE CONSTRAINT referenze_stato_verifica_check_v2;
ALTER TABLE referenze
    ADD CONSTRAINT referenze_metodo_verifica_check_v2 CHECK (
        -- email/altro restano ammessi soltanto per lo storico; il backend
        -- accetta "telefono" per le nuove verifiche con ricontatto.
        metodo_verifica IN ('nessuno', 'email', 'telefono', 'altro')
    ) NOT VALID;
ALTER TABLE referenze
    VALIDATE CONSTRAINT referenze_metodo_verifica_check_v2;

ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS email_cifrata TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS email_nonce TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS email_tag TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS email_key_id TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS email_hash TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS nome_cifrato TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS nome_nonce TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS nome_tag TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS telefono_cifrato TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS telefono_nonce TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS telefono_tag TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS messaggio_invito_cifrato TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS messaggio_invito_nonce TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS messaggio_invito_tag TEXT;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS token_hash TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS token_consumed_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS ultimo_invio_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS numero_invii INTEGER
    NOT NULL DEFAULT 0;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS aperto_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS ultimo_errore_invio TEXT;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS contatto_purge_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti
    ADD COLUMN IF NOT EXISTS contatto_purged_at TIMESTAMPTZ;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
    NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE referenze_contatti ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
    NOT NULL DEFAULT CURRENT_TIMESTAMP;

UPDATE referenze_contatti
SET telefono_cifrato = NULL,
    telefono_nonce = NULL,
    telefono_tag = NULL
WHERE NOT (
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
);

DO $reference_phone_constraint_repair$
DECLARE
    constraint_row RECORD;
BEGIN
    FOR constraint_row IN
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = 'public.referenze_contatti'::regclass
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ILIKE '%telefono_cifrato%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.referenze_contatti DROP CONSTRAINT %I',
            constraint_row.conname
        );
    END LOOP;
END
$reference_phone_constraint_repair$;

ALTER TABLE referenze_contatti
    ADD CONSTRAINT referenze_contatti_telefono_check_v2 CHECK (
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
    ) NOT VALID;
ALTER TABLE referenze_contatti
    VALIDATE CONSTRAINT referenze_contatti_telefono_check_v2;

ALTER TABLE referenze_eventi
    ADD COLUMN IF NOT EXISTS attore_utente_id INTEGER
    REFERENCES utenti(id) ON DELETE SET NULL;
ALTER TABLE referenze_eventi ADD COLUMN IF NOT EXISTS dettagli_snapshot TEXT;
ALTER TABLE referenze_eventi ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ
    NOT NULL DEFAULT CURRENT_TIMESTAMP;

DO $reference_actor_repair$
DECLARE
    constraint_row RECORD;
BEGIN
    FOR constraint_row IN
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = 'public.referenze_eventi'::regclass
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ILIKE '%attore_tipo%'
          AND pg_get_constraintdef(con.oid) ILIKE '%utente%'
    LOOP
        EXECUTE format(
            'ALTER TABLE public.referenze_eventi DROP CONSTRAINT %I',
            constraint_row.conname
        );
    END LOOP;
END
$reference_actor_repair$;

ALTER TABLE referenze_eventi
    ADD CONSTRAINT referenze_eventi_attore_tipo_check_v2 CHECK (
        attore_tipo IN ('utente', 'referente', 'admin', 'sistema')
    ) NOT VALID;
ALTER TABLE referenze_eventi
    VALIDATE CONSTRAINT referenze_eventi_attore_tipo_check_v2;

CREATE UNIQUE INDEX IF NOT EXISTS uq_referenze_contatti_referenza
    ON referenze_contatti (referenza_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_referenze_contatti_token
    ON referenze_contatti (token_hash)
    WHERE token_hash IS NOT NULL;
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
        RAISE NOTICE
            'Permessi localcare_app non applicati: privilegi insufficienti.';
END
$grants$;

COMMIT;
