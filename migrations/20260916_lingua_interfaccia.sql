\set ON_ERROR_STOP on

BEGIN;

ALTER TABLE utenti
ADD COLUMN IF NOT EXISTS lingua_interfaccia VARCHAR(5)
NOT NULL DEFAULT 'it';

UPDATE utenti
SET lingua_interfaccia = 'it'
WHERE lingua_interfaccia IS NULL
   OR TRIM(lingua_interfaccia) = '';

COMMIT;
