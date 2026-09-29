BEGIN;

ALTER TABLE annunci
ADD COLUMN IF NOT EXISTS disponibilita_cercata_json TEXT;

COMMENT ON COLUMN annunci.disponibilita_cercata_json IS
'Calendario settimanale strutturato richiesto da un annuncio di tipo cerco; non contiene testo libero o recapiti.';

COMMIT;
