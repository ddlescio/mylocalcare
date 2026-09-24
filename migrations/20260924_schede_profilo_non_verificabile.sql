-- Aggiunge l'esito amministrativo "non verificabile" senza confonderlo con
-- una verifica svolta che non ha confermato quanto dichiarato dall'utente.
-- Eseguire su PostgreSQL prima del deploy del codice applicativo.

BEGIN;

ALTER TABLE schede_profilo
DROP CONSTRAINT IF EXISTS schede_profilo_stato_verifica_check;

ALTER TABLE schede_profilo
ADD CONSTRAINT schede_profilo_stato_verifica_check CHECK (
    stato_verifica IN (
        'dichiarata', 'richiesta', 'documento_visionato',
        'riscontro_effettuato', 'non_confermata', 'non_verificabile',
        'scaduta', 'revocata'
    )
) NOT VALID;

ALTER TABLE schede_profilo
VALIDATE CONSTRAINT schede_profilo_stato_verifica_check;

ALTER TABLE schede_profilo_verifiche
DROP CONSTRAINT IF EXISTS schede_profilo_verifiche_stato_check;

ALTER TABLE schede_profilo_verifiche
ADD CONSTRAINT schede_profilo_verifiche_stato_check CHECK (
    stato IN (
        'dichiarata', 'richiesta', 'documento_visionato',
        'riscontro_effettuato', 'non_confermata', 'non_verificabile',
        'scaduta', 'revocata'
    )
) NOT VALID;

ALTER TABLE schede_profilo_verifiche
VALIDATE CONSTRAINT schede_profilo_verifiche_stato_check;

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT conrelid::regclass AS tabella, conname,
--        pg_get_constraintdef(oid) AS definizione
-- FROM pg_constraint
-- WHERE conname IN (
--     'schede_profilo_stato_verifica_check',
--     'schede_profilo_verifiche_stato_check'
-- );
