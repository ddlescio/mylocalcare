-- Bonifica una tantum delle disponibilita rimaste dopo la trasformazione,
-- disattivazione o eliminazione dell'ultimo annuncio OFFRO.
--
-- Una disponibilita e pertinente soltanto finche esiste almeno un annuncio
-- OFFRO pubblicabile, pubblico o archiviato esclusivamente per scadenza della
-- disponibilita. Le preferenze offro_* del profilo non sono un annuncio.
--
-- PRECONDIZIONE OPERATIVA: sospendere il cron dei promemoria e attendere che
-- ogni worker di consegna gia avviato sia fermato prima dell'esecuzione. Il
-- lock dell'outbox impedisce nuove letture, ma non puo revocare un messaggio
-- che un worker abbia gia caricato in memoria fra due commit per canale.

BEGIN;

-- Stabilizza lo snapshot rispetto alle modifiche degli annunci e alla
-- consegna dell'outbox mentre questa bonifica e in corso. SHARE blocca le
-- scritture sugli annunci senza impedirne le letture; ACCESS EXCLUSIVE blocca
-- nuove letture e scritture dell'outbox fino al COMMIT.
LOCK TABLE annunci IN SHARE MODE;
LOCK TABLE disponibilita_promemoria_eventi IN ACCESS EXCLUSIVE MODE;

-- Materializza una sola volta gli ambiti realmente offerti. ``annunci.categoria``
-- contiene sia slug sia vecchie etichette (per esempio "Caffè & parole"):
-- la normalizzazione seguente replica, per le categorie ammesse, ``to_slug``.
-- In questo modo la bonifica non elimina una disponibilita valida solo perche
-- l'annuncio e stato salvato prima dell'introduzione degli slug canonici.
CREATE TEMP TABLE _utenti_con_offerte_attive (
    utente_id INTEGER PRIMARY KEY
) ON COMMIT DROP;

INSERT INTO _utenti_con_offerte_attive (utente_id)
SELECT DISTINCT annuncio.utente_id
FROM annunci annuncio
WHERE annuncio.tipo_annuncio = 'offro'
  AND annuncio.stato IN (
      'in_attesa', 'approvato', 'archiviato_disponibilita'
  )
ON CONFLICT (utente_id) DO NOTHING;

CREATE TEMP TABLE _disponibilita_offerte_attive (
    utente_id INTEGER NOT NULL,
    categoria_slug TEXT NOT NULL,
    PRIMARY KEY (utente_id, categoria_slug)
) ON COMMIT DROP;

WITH categorie_normalizzate_raw AS (
    SELECT
        annuncio.utente_id,
        TRIM(BOTH '-' FROM REGEXP_REPLACE(
            REGEXP_REPLACE(
                TRANSLATE(
                    LOWER(TRIM(COALESCE(annuncio.categoria, ''))),
                    'àèéìòù_&',
                    'aeeiou  '
                ),
                '[^a-z0-9-]+',
                '-',
                'g'
            ),
            '-+',
            '-',
            'g'
        )) AS categoria_slug
    FROM annunci annuncio
    WHERE annuncio.tipo_annuncio = 'offro'
      AND annuncio.stato IN (
          'in_attesa', 'approvato', 'archiviato_disponibilita'
      )
), categorie_normalizzate AS (
    SELECT
        utente_id,
        CASE categoria_slug
            WHEN 'petsitter' THEN 'pet-sitter'
            WHEN 'sport' THEN 'escursioni-sport'
            ELSE categoria_slug
        END AS categoria_slug
    FROM categorie_normalizzate_raw
)
INSERT INTO _disponibilita_offerte_attive (utente_id, categoria_slug)
SELECT DISTINCT utente_id, categoria_slug
FROM categorie_normalizzate
WHERE categoria_slug IN (
    'operatori-benessere', 'aiuto-in-casa', 'ripetizioni',
    'babysitter', 'pet-sitter', 'caregiver', 'escursioni-sport',
    'biglietti-spettacoli', 'libri-scuola', 'caffe-parole',
    'family-kids', 'eventi-socialita', 'spazi-sale'
)
ON CONFLICT (utente_id, categoria_slug) DO NOTHING;

-- Cicli ed eventi appartengono al singolo annuncio e non devono sopravvivere
-- se quel record non e piu un servizio OFFRO utilizzabile.
DELETE FROM annunci_disponibilita_eventi evento
WHERE NOT EXISTS (
    SELECT 1
    FROM annunci annuncio
    WHERE annuncio.id = evento.annuncio_id
      AND annuncio.tipo_annuncio = 'offro'
      AND annuncio.stato IN (
          'in_attesa', 'approvato', 'archiviato_disponibilita'
      )
);

DELETE FROM annunci_disponibilita_ciclo ciclo
WHERE NOT EXISTS (
    SELECT 1
    FROM annunci annuncio
    WHERE annuncio.id = ciclo.annuncio_id
      AND annuncio.tipo_annuncio = 'offro'
      AND annuncio.stato IN (
          'in_attesa', 'approvato', 'archiviato_disponibilita'
      )
);

-- Le eccezioni per categoria esistono solo se quella categoria e ancora
-- offerta da almeno un annuncio rilevante dello stesso utente.
DELETE FROM disponibilita_profili_categoria profilo
WHERE NOT EXISTS (
    SELECT 1
    FROM _disponibilita_offerte_attive offerta
    WHERE offerta.utente_id = profilo.utente_id
      AND offerta.categoria_slug = profilo.categoria_slug
);

-- Le tabelle generali storiche puntano direttamente all'utente, non al parent:
-- vanno quindi pulite esplicitamente prima di disponibilita_profili.
DELETE FROM disponibilita_intervalli intervallo
WHERE NOT EXISTS (
    SELECT 1
    FROM _utenti_con_offerte_attive utente
    WHERE utente.utente_id = intervallo.utente_id
);

DELETE FROM disponibilita_settimanale riga
WHERE NOT EXISTS (
    SELECT 1
    FROM _utenti_con_offerte_attive utente
    WHERE utente.utente_id = riga.utente_id
);

DELETE FROM disponibilita_date_speciali data_speciale
WHERE NOT EXISTS (
    SELECT 1
    FROM _utenti_con_offerte_attive utente
    WHERE utente.utente_id = data_speciale.utente_id
);

DELETE FROM disponibilita_assenze assenza
WHERE NOT EXISTS (
    SELECT 1
    FROM _utenti_con_offerte_attive utente
    WHERE utente.utente_id = assenza.utente_id
);

DELETE FROM disponibilita_profili profilo
WHERE NOT EXISTS (
    SELECT 1
    FROM _utenti_con_offerte_attive utente
    WHERE utente.utente_id = profilo.utente_id
);

-- Non consegnare avvisi ancora pendenti a utenti che non offrono piu alcun
-- servizio, ne avvisi specifici per una categoria che non offrono piu. Gli
-- eventi gia consegnati restano nello storico operativo.
DELETE FROM disponibilita_promemoria_eventi evento
WHERE (
        evento.notifica_interna_at IS NULL
        OR evento.push_inviata_at IS NULL
        OR evento.email_inviata_at IS NULL
      )
  AND (
      NOT EXISTS (
          SELECT 1
          FROM _utenti_con_offerte_attive utente
          WHERE utente.utente_id = evento.utente_id
      )
      OR (
          POSITION('categoria=' IN evento.link) > 0
          AND NOT EXISTS (
              SELECT 1
              FROM _disponibilita_offerte_attive offerta
              WHERE offerta.utente_id = evento.utente_id
                AND offerta.categoria_slug = SPLIT_PART(
                    SPLIT_PART(evento.link, 'categoria=', 2),
                    '&',
                    1
                )
          )
      )
  );

COMMIT;

-- Verifica post-migrazione (deve restituire zero):
-- SELECT COUNT(*)
-- FROM disponibilita_profili profilo
-- WHERE NOT EXISTS (
--   SELECT 1 FROM annunci annuncio
--   WHERE annuncio.utente_id = profilo.utente_id
--     AND annuncio.tipo_annuncio = 'offro'
--     AND annuncio.stato IN (
--       'in_attesa', 'approvato', 'archiviato_disponibilita'
--     )
-- );
