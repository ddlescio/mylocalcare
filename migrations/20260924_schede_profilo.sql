-- Schede strutturate per esperienze, formazione e certificazioni.
-- Non modifica e non cancella i campi testuali storici presenti in utenti.
-- Eseguire su PostgreSQL prima del deploy del codice applicativo.

BEGIN;

CREATE TABLE IF NOT EXISTS catalogo_qualifiche (
    id BIGSERIAL PRIMARY KEY,
    codice TEXT NOT NULL UNIQUE,
    titolo TEXT NOT NULL,
    tipo_scheda TEXT NOT NULL CHECK (
        tipo_scheda IN ('esperienza', 'formazione', 'certificazione')
    ),
    natura TEXT NOT NULL,
    descrizione TEXT,
    richiede_ente BOOLEAN NOT NULL DEFAULT FALSE,
    prevede_scadenza BOOLEAN NOT NULL DEFAULT FALSE,
    professione_regolamentata BOOLEAN NOT NULL DEFAULT FALSE,
    ordine INTEGER NOT NULL DEFAULT 100,
    attivo BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS catalogo_qualifiche_categorie (
    catalogo_id BIGINT NOT NULL
        REFERENCES catalogo_qualifiche(id) ON DELETE CASCADE,
    categoria_slug TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (catalogo_id, categoria_slug)
);

CREATE TABLE IF NOT EXISTS schede_profilo (
    id BIGSERIAL PRIMARY KEY,
    utente_id INTEGER NOT NULL
        REFERENCES utenti(id) ON DELETE CASCADE,
    legacy_key TEXT NOT NULL CHECK (legacy_key IN (
        'esperienza_1', 'esperienza_2', 'esperienza_3',
        'studio_1', 'studio_2', 'studio_3', 'certificazioni'
    )),
    tipo_scheda TEXT NOT NULL CHECK (
        tipo_scheda IN ('esperienza', 'formazione', 'certificazione')
    ),
    catalogo_id BIGINT
        REFERENCES catalogo_qualifiche(id) ON DELETE SET NULL,
    titolo TEXT NOT NULL,
    categoria_slug TEXT,
    ente TEXT,
    luogo TEXT,
    data_inizio DATE,
    data_fine DATE,
    in_corso BOOLEAN NOT NULL DEFAULT FALSE,
    data_rilascio DATE,
    data_scadenza DATE,
    codice_qualifica TEXT,
    descrizione TEXT,
    attiva BOOLEAN NOT NULL DEFAULT TRUE,
    stato_verifica TEXT NOT NULL DEFAULT 'dichiarata' CHECK (
        stato_verifica IN (
            'dichiarata', 'richiesta', 'documento_visionato',
            'riscontro_effettuato', 'non_confermata',
            'non_verificabile', 'scaduta', 'revocata'
        )
    ),
    richiesta_verifica_at TIMESTAMPTZ,
    verificata_at TIMESTAMPTZ,
    verificata_da_admin_id INTEGER
        REFERENCES utenti(id) ON DELETE SET NULL,
    metodo_verifica TEXT NOT NULL DEFAULT 'nessuno' CHECK (
        metodo_verifica IN (
            'nessuno', 'documento', 'fonte_pubblica',
            'ente_contattato', 'altro'
        )
    ),
    nota_pubblica TEXT,
    versione INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (legacy_key IN (
            'esperienza_1', 'esperienza_2', 'esperienza_3'
        ) AND tipo_scheda = 'esperienza')
        OR (legacy_key IN (
            'studio_1', 'studio_2', 'studio_3'
        ) AND tipo_scheda = 'formazione')
        OR (legacy_key = 'certificazioni'
            AND tipo_scheda = 'certificazione')
    ),
    CHECK (
        data_fine IS NULL OR data_inizio IS NULL
        OR data_fine >= data_inizio
    ),
    CHECK (
        data_scadenza IS NULL OR data_rilascio IS NULL
        OR data_scadenza >= data_rilascio
    )
);

ALTER TABLE schede_profilo
ADD COLUMN IF NOT EXISTS versione INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS schede_profilo_verifiche (
    id BIGSERIAL PRIMARY KEY,
    scheda_id BIGINT NOT NULL
        REFERENCES schede_profilo(id) ON DELETE CASCADE,
    stato TEXT NOT NULL CHECK (stato IN (
        'dichiarata', 'richiesta', 'documento_visionato',
        'riscontro_effettuato', 'non_confermata', 'non_verificabile',
        'scaduta', 'revocata'
    )),
    metodo TEXT NOT NULL DEFAULT 'nessuno' CHECK (metodo IN (
        'nessuno', 'documento', 'fonte_pubblica',
        'ente_contattato', 'altro'
    )),
    nota_admin TEXT,
    nota_pubblica TEXT,
    scheda_snapshot TEXT,
    admin_id INTEGER REFERENCES utenti(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE schede_profilo_verifiche
ADD COLUMN IF NOT EXISTS scheda_snapshot TEXT;

CREATE INDEX IF NOT EXISTS idx_catalogo_qualifiche_elenco
    ON catalogo_qualifiche (attivo, tipo_scheda, ordine, titolo);

CREATE INDEX IF NOT EXISTS idx_catalogo_qualifiche_categoria
    ON catalogo_qualifiche_categorie (categoria_slug, catalogo_id);

CREATE INDEX IF NOT EXISTS idx_schede_profilo_utente
    ON schede_profilo (utente_id, attiva, legacy_key, created_at);

CREATE INDEX IF NOT EXISTS idx_schede_profilo_verifica
    ON schede_profilo (stato_verifica, richiesta_verifica_at);

CREATE INDEX IF NOT EXISTS idx_schede_profilo_catalogo
    ON schede_profilo (catalogo_id);

CREATE INDEX IF NOT EXISTS idx_schede_profilo_verifiche_storico
    ON schede_profilo_verifiche (scheda_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_schede_profilo_slot_singolo_attivo
    ON schede_profilo (utente_id, legacy_key)
    WHERE attiva = TRUE AND legacy_key <> 'certificazioni';

-- Il seed inserisce solo voci mancanti: titoli, ordine e stato eventualmente
-- modificati dall'admin non vengono sovrascritti.
INSERT INTO catalogo_qualifiche (
    codice, titolo, tipo_scheda, natura, richiede_ente,
    prevede_scadenza, professione_regolamentata, ordine
)
VALUES
    ('exp_babysitter', 'Babysitter', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 10),
    ('exp_tata', 'Tata', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 11),
    ('exp_educatore_infanzia', 'Educatore per l''infanzia', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 12),
    ('exp_animatore_bambini', 'Animatore per bambini', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 13),
    ('exp_colf', 'Collaboratore domestico / Colf', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 20),
    ('exp_assistente_familiare', 'Assistente familiare', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 21),
    ('exp_badante', 'Assistente a persone anziane / Badante', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 22),
    ('exp_oss', 'Operatore Socio Sanitario (OSS)', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 23),
    ('exp_asa', 'Ausiliario Socio Assistenziale (ASA)', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 24),
    ('exp_pet_sitter', 'Pet sitter', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 30),
    ('exp_dog_sitter', 'Dog sitter', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 31),
    ('exp_cat_sitter', 'Cat sitter', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 32),
    ('exp_educatore_cinofilo', 'Educatore cinofilo', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 33),
    ('exp_tutor', 'Tutor scolastico', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 40),
    ('exp_insegnante', 'Insegnante', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 41),
    ('exp_docente_lingue', 'Insegnante di lingue', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 42),
    ('exp_personal_trainer', 'Personal trainer', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 50),
    ('exp_istruttore_sportivo', 'Istruttore sportivo', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 51),
    ('exp_guida_escursionistica', 'Guida escursionistica', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 52),
    ('exp_operatore_benessere', 'Operatore del benessere', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 53),
    ('exp_massaggiatore', 'Massaggiatore', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 54),
    ('exp_insegnante_yoga', 'Insegnante di yoga', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 55),
    ('exp_insegnante_pilates', 'Insegnante di Pilates', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 56),
    ('exp_organizzatore_eventi', 'Organizzatore di eventi', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 60),
    ('exp_gestore_spazi', 'Gestore di spazi o sale', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 61),
    ('exp_accoglienza_eventi', 'Esperienza in accoglienza o biglietteria eventi', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 62),
    ('exp_libreria_editoria', 'Esperienza in libreria, biblioteca o editoria', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 63),
    ('exp_facilitatore_sociale', 'Facilitatore di incontri o attività sociali', 'esperienza', 'esperienza', FALSE, FALSE, FALSE, 64),
    ('form_diploma_servizi_sociali', 'Diploma in servizi socio-sanitari', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 100),
    ('form_laurea_scienze_educazione', 'Laurea in Scienze dell''educazione', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 101),
    ('form_laurea_pedagogia', 'Laurea in Pedagogia', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 102),
    ('form_laurea_psicologia', 'Laurea in Psicologia', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 103),
    ('form_laurea_infermieristica', 'Laurea in Infermieristica', 'formazione', 'titolo_studio', TRUE, FALSE, TRUE, 104),
    ('form_laurea_fisioterapia', 'Laurea in Fisioterapia', 'formazione', 'titolo_studio', TRUE, FALSE, TRUE, 105),
    ('form_laurea_logopedia', 'Laurea in Logopedia', 'formazione', 'titolo_studio', TRUE, FALSE, TRUE, 106),
    ('form_laurea_terapia_occupazionale', 'Laurea in Terapia occupazionale', 'formazione', 'titolo_studio', TRUE, FALSE, TRUE, 107),
    ('form_laurea_scienze_motorie', 'Laurea in Scienze motorie', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 108),
    ('form_laurea_nutrizione', 'Laurea pertinente all''ambito nutrizione', 'formazione', 'titolo_studio', TRUE, FALSE, TRUE, 109),
    ('form_laurea_veterinaria', 'Laurea in Medicina veterinaria', 'formazione', 'titolo_studio', TRUE, FALSE, TRUE, 110),
    ('form_tecnico_veterinario', 'Percorso per tecnico veterinario', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 111),
    ('form_diploma', 'Diploma di scuola secondaria', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 112),
    ('form_laurea_generica', 'Laurea', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 113),
    ('form_master', 'Master universitario', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 114),
    ('form_dottorato', 'Dottorato di ricerca', 'formazione', 'titolo_studio', TRUE, FALSE, FALSE, 115),
    ('form_qualifica_oss', 'Qualifica di Operatore Socio Sanitario (OSS)', 'formazione', 'qualifica_professionale', TRUE, FALSE, FALSE, 120),
    ('form_qualifica_asa', 'Qualifica di Ausiliario Socio Assistenziale (ASA)', 'formazione', 'qualifica_professionale', TRUE, FALSE, FALSE, 121),
    ('form_qualifica_osa', 'Qualifica di Operatore Socio Assistenziale (OSA)', 'formazione', 'qualifica_professionale', TRUE, FALSE, FALSE, 122),
    ('form_assistente_familiare', 'Corso per assistente familiare', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 123),
    ('form_assistente_infanzia', 'Corso per assistenza all''infanzia', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 124),
    ('form_educatore_cinofilo', 'Corso per educatore cinofilo', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 125),
    ('form_toelettatura', 'Corso di toelettatura', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 126),
    ('form_massaggio', 'Corso di massaggio', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 127),
    ('form_yoga', 'Formazione per insegnante di yoga', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 128),
    ('form_pilates', 'Formazione per insegnante di Pilates', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 129),
    ('form_animazione', 'Corso di animazione e intrattenimento', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 130),
    ('form_eventi', 'Corso in organizzazione di eventi', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 131),
    ('form_turismo_accoglienza', 'Formazione in turismo, accoglienza o biglietteria', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 132),
    ('form_biblioteconomia_editoria', 'Formazione in biblioteconomia, libreria o editoria', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 133),
    ('form_mediazione_culturale', 'Formazione in mediazione culturale o facilitazione', 'formazione', 'percorso_formativo', TRUE, FALSE, FALSE, 134),
    ('cert_primo_soccorso', 'Attestato di primo soccorso', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 200),
    ('cert_primo_soccorso_pediatrico', 'Attestato di primo soccorso pediatrico', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 201),
    ('cert_blsd', 'Attestato BLSD', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 202),
    ('cert_disostruzione_pediatrica', 'Corso di disostruzione pediatrica', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 203),
    ('cert_haccp', 'Attestato HACCP', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 204),
    ('cert_antincendio', 'Attestato antincendio', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 205),
    ('cert_sicurezza_lavoro', 'Formazione sulla sicurezza sul lavoro', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 206),
    ('cert_pet_first_aid', 'Corso di primo soccorso per animali', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 210),
    ('cert_educatore_cinofilo', 'Qualifica o attestato di educatore cinofilo', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 211),
    ('cert_addestratore_cinofilo', 'Qualifica o attestato di addestratore cinofilo', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 212),
    ('cert_operatore_pet_therapy', 'Formazione in interventi assistiti con animali', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 213),
    ('cert_lingua_inglese', 'Certificazione di lingua inglese', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 220),
    ('cert_lingua_francese', 'Certificazione di lingua francese', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 221),
    ('cert_lingua_spagnola', 'Certificazione di lingua spagnola', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 222),
    ('cert_lingua_tedesca', 'Certificazione di lingua tedesca', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 223),
    ('cert_italiano_stranieri', 'Certificazione per l''insegnamento dell''italiano a stranieri', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 224),
    ('cert_dsa_bes', 'Formazione o attestato DSA/BES', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 225),
    ('cert_insegnamento', 'Abilitazione all''insegnamento', 'certificazione', 'abilitazione', TRUE, FALSE, TRUE, 226),
    ('cert_albo_psicologi', 'Iscrizione all''Albo degli Psicologi', 'certificazione', 'iscrizione_albo', TRUE, TRUE, TRUE, 230),
    ('cert_albo_fisioterapisti', 'Iscrizione all''Albo dei Fisioterapisti', 'certificazione', 'iscrizione_albo', TRUE, TRUE, TRUE, 231),
    ('cert_albo_infermieri', 'Iscrizione all''Ordine delle Professioni Infermieristiche', 'certificazione', 'iscrizione_albo', TRUE, TRUE, TRUE, 232),
    ('cert_albo_nutrizione', 'Iscrizione all''albo professionale pertinente alla nutrizione', 'certificazione', 'iscrizione_albo', TRUE, TRUE, TRUE, 233),
    ('cert_tessera_tecnica_sport', 'Qualifica tecnica sportiva', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 240),
    ('cert_istruttore_federale', 'Qualifica di istruttore federale', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 241),
    ('cert_guida_ambientale', 'Abilitazione o qualifica di guida ambientale escursionistica', 'certificazione', 'abilitazione', TRUE, TRUE, FALSE, 242),
    ('cert_salvamento', 'Brevetto di assistente bagnanti', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 243),
    ('cert_yoga', 'Certificazione per insegnamento yoga', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 244),
    ('cert_pilates', 'Certificazione per insegnamento Pilates', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 245),
    ('cert_personal_trainer', 'Certificazione di personal trainer', 'certificazione', 'corso_attestato', TRUE, TRUE, FALSE, 246),
    ('cert_massage', 'Attestato in tecniche di massaggio', 'certificazione', 'corso_attestato', TRUE, FALSE, FALSE, 247)
ON CONFLICT (codice) DO NOTHING;

INSERT INTO catalogo_qualifiche_categorie (catalogo_id, categoria_slug)
SELECT catalogo.id, seed.categoria_slug
FROM (VALUES
    ('exp_babysitter', 'babysitter'),
    ('exp_babysitter', 'family-kids'),
    ('exp_tata', 'babysitter'),
    ('exp_educatore_infanzia', 'babysitter'),
    ('exp_educatore_infanzia', 'family-kids'),
    ('exp_animatore_bambini', 'family-kids'),
    ('exp_animatore_bambini', 'eventi-socialita'),
    ('exp_colf', 'aiuto-in-casa'),
    ('exp_assistente_familiare', 'caregiver'),
    ('exp_assistente_familiare', 'aiuto-in-casa'),
    ('exp_badante', 'caregiver'),
    ('exp_oss', 'caregiver'),
    ('exp_asa', 'caregiver'),
    ('exp_pet_sitter', 'pet-sitter'),
    ('exp_dog_sitter', 'pet-sitter'),
    ('exp_cat_sitter', 'pet-sitter'),
    ('exp_educatore_cinofilo', 'pet-sitter'),
    ('exp_tutor', 'ripetizioni'),
    ('exp_insegnante', 'ripetizioni'),
    ('exp_insegnante', 'caffe-parole'),
    ('exp_docente_lingue', 'ripetizioni'),
    ('exp_docente_lingue', 'caffe-parole'),
    ('exp_personal_trainer', 'operatori-benessere'),
    ('exp_personal_trainer', 'escursioni-sport'),
    ('exp_istruttore_sportivo', 'escursioni-sport'),
    ('exp_guida_escursionistica', 'escursioni-sport'),
    ('exp_operatore_benessere', 'operatori-benessere'),
    ('exp_massaggiatore', 'operatori-benessere'),
    ('exp_insegnante_yoga', 'operatori-benessere'),
    ('exp_insegnante_yoga', 'escursioni-sport'),
    ('exp_insegnante_pilates', 'operatori-benessere'),
    ('exp_insegnante_pilates', 'escursioni-sport'),
    ('exp_organizzatore_eventi', 'eventi-socialita'),
    ('exp_organizzatore_eventi', 'family-kids'),
    ('exp_organizzatore_eventi', 'spazi-sale'),
    ('exp_gestore_spazi', 'spazi-sale'),
    ('exp_accoglienza_eventi', 'biglietti-spettacoli'),
    ('exp_accoglienza_eventi', 'eventi-socialita'),
    ('exp_libreria_editoria', 'libri-scuola'),
    ('exp_facilitatore_sociale', 'caffe-parole'),
    ('exp_facilitatore_sociale', 'eventi-socialita'),
    ('form_diploma_servizi_sociali', 'caregiver'),
    ('form_diploma_servizi_sociali', 'babysitter'),
    ('form_diploma_servizi_sociali', 'family-kids'),
    ('form_laurea_scienze_educazione', 'babysitter'),
    ('form_laurea_scienze_educazione', 'family-kids'),
    ('form_laurea_scienze_educazione', 'caregiver'),
    ('form_laurea_pedagogia', 'babysitter'),
    ('form_laurea_pedagogia', 'family-kids'),
    ('form_laurea_pedagogia', 'ripetizioni'),
    ('form_laurea_psicologia', 'babysitter'),
    ('form_laurea_psicologia', 'family-kids'),
    ('form_laurea_psicologia', 'caregiver'),
    ('form_laurea_psicologia', 'operatori-benessere'),
    ('form_laurea_infermieristica', 'caregiver'),
    ('form_laurea_fisioterapia', 'operatori-benessere'),
    ('form_laurea_fisioterapia', 'caregiver'),
    ('form_laurea_logopedia', 'caregiver'),
    ('form_laurea_logopedia', 'family-kids'),
    ('form_laurea_terapia_occupazionale', 'caregiver'),
    ('form_laurea_scienze_motorie', 'escursioni-sport'),
    ('form_laurea_scienze_motorie', 'operatori-benessere'),
    ('form_laurea_nutrizione', 'operatori-benessere'),
    ('form_laurea_veterinaria', 'pet-sitter'),
    ('form_tecnico_veterinario', 'pet-sitter'),
    ('form_diploma', 'ripetizioni'),
    ('form_diploma', 'babysitter'),
    ('form_diploma', 'caffe-parole'),
    ('form_laurea_generica', 'ripetizioni'),
    ('form_laurea_generica', 'caffe-parole'),
    ('form_laurea_generica', 'eventi-socialita'),
    ('form_master', 'ripetizioni'),
    ('form_master', 'operatori-benessere'),
    ('form_master', 'caregiver'),
    ('form_master', 'family-kids'),
    ('form_dottorato', 'ripetizioni'),
    ('form_qualifica_oss', 'caregiver'),
    ('form_qualifica_asa', 'caregiver'),
    ('form_qualifica_osa', 'caregiver'),
    ('form_assistente_familiare', 'caregiver'),
    ('form_assistente_familiare', 'aiuto-in-casa'),
    ('form_assistente_infanzia', 'babysitter'),
    ('form_assistente_infanzia', 'family-kids'),
    ('form_educatore_cinofilo', 'pet-sitter'),
    ('form_toelettatura', 'pet-sitter'),
    ('form_massaggio', 'operatori-benessere'),
    ('form_yoga', 'operatori-benessere'),
    ('form_yoga', 'escursioni-sport'),
    ('form_pilates', 'operatori-benessere'),
    ('form_pilates', 'escursioni-sport'),
    ('form_animazione', 'family-kids'),
    ('form_animazione', 'eventi-socialita'),
    ('form_eventi', 'eventi-socialita'),
    ('form_eventi', 'family-kids'),
    ('form_eventi', 'spazi-sale'),
    ('form_turismo_accoglienza', 'biglietti-spettacoli'),
    ('form_turismo_accoglienza', 'eventi-socialita'),
    ('form_turismo_accoglienza', 'spazi-sale'),
    ('form_biblioteconomia_editoria', 'libri-scuola'),
    ('form_mediazione_culturale', 'caffe-parole'),
    ('form_mediazione_culturale', 'eventi-socialita'),
    ('form_mediazione_culturale', 'family-kids'),
    ('cert_primo_soccorso', 'babysitter'),
    ('cert_primo_soccorso', 'caregiver'),
    ('cert_primo_soccorso', 'escursioni-sport'),
    ('cert_primo_soccorso', 'family-kids'),
    ('cert_primo_soccorso', 'spazi-sale'),
    ('cert_primo_soccorso', 'eventi-socialita'),
    ('cert_primo_soccorso_pediatrico', 'babysitter'),
    ('cert_primo_soccorso_pediatrico', 'family-kids'),
    ('cert_blsd', 'babysitter'),
    ('cert_blsd', 'caregiver'),
    ('cert_blsd', 'escursioni-sport'),
    ('cert_blsd', 'operatori-benessere'),
    ('cert_blsd', 'family-kids'),
    ('cert_blsd', 'spazi-sale'),
    ('cert_disostruzione_pediatrica', 'babysitter'),
    ('cert_disostruzione_pediatrica', 'family-kids'),
    ('cert_haccp', 'aiuto-in-casa'),
    ('cert_haccp', 'caregiver'),
    ('cert_haccp', 'babysitter'),
    ('cert_haccp', 'family-kids'),
    ('cert_haccp', 'eventi-socialita'),
    ('cert_haccp', 'spazi-sale'),
    ('cert_antincendio', 'family-kids'),
    ('cert_antincendio', 'eventi-socialita'),
    ('cert_antincendio', 'spazi-sale'),
    ('cert_sicurezza_lavoro', 'aiuto-in-casa'),
    ('cert_sicurezza_lavoro', 'caregiver'),
    ('cert_sicurezza_lavoro', 'family-kids'),
    ('cert_sicurezza_lavoro', 'eventi-socialita'),
    ('cert_sicurezza_lavoro', 'spazi-sale'),
    ('cert_pet_first_aid', 'pet-sitter'),
    ('cert_educatore_cinofilo', 'pet-sitter'),
    ('cert_addestratore_cinofilo', 'pet-sitter'),
    ('cert_operatore_pet_therapy', 'pet-sitter'),
    ('cert_operatore_pet_therapy', 'caregiver'),
    ('cert_operatore_pet_therapy', 'family-kids'),
    ('cert_lingua_inglese', 'ripetizioni'),
    ('cert_lingua_inglese', 'babysitter'),
    ('cert_lingua_inglese', 'caffe-parole'),
    ('cert_lingua_francese', 'ripetizioni'),
    ('cert_lingua_francese', 'babysitter'),
    ('cert_lingua_francese', 'caffe-parole'),
    ('cert_lingua_spagnola', 'ripetizioni'),
    ('cert_lingua_spagnola', 'babysitter'),
    ('cert_lingua_spagnola', 'caffe-parole'),
    ('cert_lingua_tedesca', 'ripetizioni'),
    ('cert_lingua_tedesca', 'babysitter'),
    ('cert_lingua_tedesca', 'caffe-parole'),
    ('cert_italiano_stranieri', 'ripetizioni'),
    ('cert_italiano_stranieri', 'caffe-parole'),
    ('cert_dsa_bes', 'ripetizioni'),
    ('cert_dsa_bes', 'babysitter'),
    ('cert_dsa_bes', 'family-kids'),
    ('cert_insegnamento', 'ripetizioni'),
    ('cert_albo_psicologi', 'operatori-benessere'),
    ('cert_albo_psicologi', 'caregiver'),
    ('cert_albo_psicologi', 'family-kids'),
    ('cert_albo_fisioterapisti', 'operatori-benessere'),
    ('cert_albo_fisioterapisti', 'caregiver'),
    ('cert_albo_infermieri', 'caregiver'),
    ('cert_albo_nutrizione', 'operatori-benessere'),
    ('cert_tessera_tecnica_sport', 'escursioni-sport'),
    ('cert_tessera_tecnica_sport', 'operatori-benessere'),
    ('cert_istruttore_federale', 'escursioni-sport'),
    ('cert_guida_ambientale', 'escursioni-sport'),
    ('cert_salvamento', 'escursioni-sport'),
    ('cert_salvamento', 'family-kids'),
    ('cert_yoga', 'operatori-benessere'),
    ('cert_yoga', 'escursioni-sport'),
    ('cert_pilates', 'operatori-benessere'),
    ('cert_pilates', 'escursioni-sport'),
    ('cert_personal_trainer', 'operatori-benessere'),
    ('cert_personal_trainer', 'escursioni-sport'),
    ('cert_massage', 'operatori-benessere')
) AS seed(codice, categoria_slug)
JOIN catalogo_qualifiche AS catalogo ON catalogo.codice = seed.codice
ON CONFLICT (catalogo_id, categoria_slug) DO NOTHING;

COMMIT;

-- Verifica post-migrazione (sola lettura):
-- SELECT to_regclass('public.catalogo_qualifiche'),
--        to_regclass('public.schede_profilo'),
--        to_regclass('public.schede_profilo_verifiche');
-- SELECT COUNT(*) AS voci_catalogo FROM catalogo_qualifiche;
