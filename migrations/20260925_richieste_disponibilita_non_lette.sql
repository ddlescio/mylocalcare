-- Sposta richieste e risposte disponibilita dal badge notifiche al badge chat.
-- Il backfill viene eseguito soltanto quando la colonna nasce, cosi un
-- eventuale secondo avvio della migrazione non marca come letti nuovi eventi.

BEGIN;

DO $migration$
DECLARE
    colonna_mancante BOOLEAN;
BEGIN
    SELECT NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'richieste_disponibilita'
          AND column_name = 'evento_letto_at'
    ) INTO colonna_mancante;

    IF colonna_mancante THEN
        ALTER TABLE richieste_disponibilita
            ADD COLUMN evento_letto_at TIMESTAMPTZ;

        -- Gli eventi precedenti al rilascio non devono comparire tutti insieme
        -- come nuove chat non lette.
        UPDATE richieste_disponibilita
        SET evento_letto_at = COALESCE(
            updated_at,
            created_at,
            CURRENT_TIMESTAMP
        )
        WHERE evento_letto_at IS NULL;
    END IF;
END
$migration$;

CREATE INDEX IF NOT EXISTS idx_richieste_disponibilita_offerente_non_lette
    ON richieste_disponibilita (offerente_id, updated_at DESC)
    WHERE evento_letto_at IS NULL
      AND stato = 'in_attesa';

CREATE INDEX IF NOT EXISTS idx_richieste_disponibilita_richiedente_non_lette
    ON richieste_disponibilita (richiedente_id, updated_at DESC)
    WHERE evento_letto_at IS NULL
      AND stato IN ('disponibile', 'non_disponibile', 'informazioni');

-- Le vecchie righe restano nello storico, ma non continuano a gonfiare la
-- campanella dopo il passaggio della funzione alla conversazione chat.
UPDATE notifiche
SET letta = 1
WHERE letta = 0
  AND tipo IN ('richiesta_disponibilita', 'risposta_disponibilita');

COMMIT;
