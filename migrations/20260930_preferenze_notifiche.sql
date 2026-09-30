-- Preferenza account per le notifiche push.
--
-- Il valore e' attivo per impostazione predefinita, ma la consegna resta
-- subordinata all'autorizzazione esplicita del browser/dispositivo e alla
-- presenza di una subscription valida.

BEGIN;

ALTER TABLE utenti
ADD COLUMN IF NOT EXISTS push_notifiche INTEGER;

UPDATE utenti
SET push_notifiche = 1
WHERE push_notifiche IS NULL;

ALTER TABLE utenti
ALTER COLUMN push_notifiche SET DEFAULT 1;

ALTER TABLE utenti
ALTER COLUMN push_notifiche SET NOT NULL;

COMMIT;

-- Verifica post-migrazione:
-- SELECT push_notifiche, COUNT(*) FROM utenti GROUP BY push_notifiche;
