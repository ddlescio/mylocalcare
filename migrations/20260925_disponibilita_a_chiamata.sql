-- Opzione additiva "A chiamata" per la disponibilita generale e per servizio.
-- Puo essere usata da sola oppure insieme a giorni e fasce settimanali.

BEGIN;

ALTER TABLE disponibilita_profili
    ADD COLUMN IF NOT EXISTS a_chiamata BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE disponibilita_profili_categoria
    ADD COLUMN IF NOT EXISTS a_chiamata BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT table_name, column_name, column_default, is_nullable
-- FROM information_schema.columns
-- WHERE table_schema = 'public'
--   AND table_name IN (
--       'disponibilita_profili',
--       'disponibilita_profili_categoria'
--   )
--   AND column_name = 'a_chiamata';
