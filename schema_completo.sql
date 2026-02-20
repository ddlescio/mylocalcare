CREATE TABLE utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        cognome TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        ruolo TEXT DEFAULT 'user',
        attivo INTEGER DEFAULT 0,
        token_verifica TEXT,

        -- 📸 Immagini
        foto_profilo TEXT,
        copertina TEXT,

        -- 🧩 Info di base
        citta TEXT,
        macro_area TEXT,
        provincia TEXT,
        regione TEXT,
        lingue TEXT,
        frase TEXT,

        -- 🔹 Attività (Cerco / Offro)
        offro_1 INTEGER DEFAULT 0,
        offro_2 INTEGER DEFAULT 0,
        offro_3 INTEGER DEFAULT 0,
        offro_4 INTEGER DEFAULT 0,
        offro_5 INTEGER DEFAULT 0,
        offro_6 INTEGER DEFAULT 0,
        offro_7 INTEGER DEFAULT 0,
        offro_8 INTEGER DEFAULT 0,
        offro_9 INTEGER DEFAULT 0,
        offro_10 INTEGER DEFAULT 0,
        cerco_1 INTEGER DEFAULT 0,
        cerco_2 INTEGER DEFAULT 0,
        cerco_3 INTEGER DEFAULT 0,
        cerco_4 INTEGER DEFAULT 0,
        cerco_5 INTEGER DEFAULT 0,
        cerco_6 INTEGER DEFAULT 0,
        cerco_7 INTEGER DEFAULT 0,
        cerco_8 INTEGER DEFAULT 0,
        cerco_9 INTEGER DEFAULT 0,
        cerco_10 INTEGER DEFAULT 0,

        -- 📞 Contatti e presenza online
        telefono TEXT,
        email_pubblica TEXT,
        indirizzo_studio TEXT,
        sito_web TEXT,
        instagram TEXT,
        facebook TEXT,
        linkedin TEXT,
        orari TEXT,
        preferenze_contatto TEXT,

        -- 🧠 Lavoro e formazione
        esperienza_1 TEXT,
        esperienza_2 TEXT,
        esperienza_3 TEXT,
        studio_1 TEXT,
        studio_2 TEXT,
        studio_3 TEXT,
        certificazioni TEXT,

        -- 📝 Descrizione profilo
        descrizione TEXT,

        -- 🌐 Visibilità e impostazioni
        visibile_pubblicamente INTEGER DEFAULT 1,
        visibile_in_chat INTEGER DEFAULT 1,
        sospeso INTEGER DEFAULT 0,
        disattivato_admin INTEGER DEFAULT 0,
        email_notifiche INTEGER DEFAULT 1,

        -- ⭐ Riepilogo recensioni
        media_recensioni REAL DEFAULT 0,
        numero_recensioni INTEGER DEFAULT 0,

        -- 🕒 Data creazione
        data_creazione TEXT DEFAULT (datetime('now')),

        -- 📸 Galleria immagini
        foto_galleria TEXT,

        -- 🔐 Chiavi di cifratura (DEK + ID chiave + X25519)
        key_salt TEXT,
        dek_enc TEXT,
        dek_nonce TEXT,
        dek_mk_enc TEXT,
        dek_mk_nonce TEXT,
        id_pub TEXT,
        id_priv_enc TEXT,
        id_priv_nonce TEXT,
        x25519_pub TEXT,
        x25519_priv_enc TEXT,
        x25519_priv_nonce TEXT,

        -- 🔐 Sicurezza login / admin
        failed_logins INTEGER DEFAULT 0,
        lock_until TEXT,
        admin_session_token TEXT,
        admin_session_expiry TEXT,
        admin_browser_fingerprint TEXT,

        -- 🛡️ Verifica maggiore età
        maggiorenne_verificato INTEGER DEFAULT 0,
        data_verifica_maggiorenne TEXT,
        ip_verifica_maggiorenne TEXT,
        versione_consenso TEXT
    );
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE operatori (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_utente INTEGER,
        nome TEXT NOT NULL,
        categoria TEXT NOT NULL,
        comune TEXT,
        zona TEXT,
        servizi TEXT,
        prezzo TEXT,
        bio TEXT,
        filtri_categoria TEXT,
        visibile_pubblicamente INTEGER DEFAULT 1,
        foto_profilo TEXT,
        media_recensioni REAL DEFAULT 0,
        numero_recensioni INTEGER DEFAULT 0,
        FOREIGN KEY (id_utente) REFERENCES utenti(id)
    );
CREATE TABLE annunci (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        utente_id INTEGER NOT NULL,
        username TEXT,
        categoria TEXT NOT NULL,
        tipo_annuncio TEXT CHECK(tipo_annuncio IN ('offro','cerco')),
        filtri_categoria TEXT,
        zona TEXT,
        provincia TEXT,
        titolo TEXT NOT NULL,
        descrizione TEXT,
        bio_utente TEXT,
        media TEXT,
        prezzo TEXT,
        telefono TEXT,
        email TEXT,
        data_pubblicazione TEXT DEFAULT (datetime('now')),
        stato TEXT DEFAULT 'in_attesa',
        urgente INTEGER DEFAULT 0,
        approvato_il TEXT,
        match_da_processare INTEGER DEFAULT 0,
        ultima_notifica_urgente TEXT,
        FOREIGN KEY (utente_id) REFERENCES utenti(id)
    );
CREATE UNIQUE INDEX idx_one_active_ad_per_category
        ON annunci(utente_id, categoria)
        WHERE stato IN ('in_attesa', 'approvato');
CREATE TABLE match_utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        -- chi cerca e chi offre
        utente_cerca_id INTEGER NOT NULL,
        utente_offre_id INTEGER NOT NULL,

        categoria TEXT NOT NULL,
        zona TEXT,

        -- annuncio che ha generato il match (di solito quello “nuovo approvato”)
        annuncio_id INTEGER NOT NULL,

        created_at TEXT DEFAULT (datetime('now')),
        notificato INTEGER DEFAULT 0,

        FOREIGN KEY (utente_cerca_id) REFERENCES utenti(id),
        FOREIGN KEY (utente_offre_id) REFERENCES utenti(id),
        FOREIGN KEY (annuncio_id) REFERENCES annunci(id),

        -- evita duplicati identici (stesso annuncio, stessi due utenti)
        UNIQUE (utente_cerca_id, utente_offre_id, annuncio_id)
    );
CREATE INDEX idx_match_cerca ON match_utenti(utente_cerca_id, notificato);
CREATE INDEX idx_match_annuncio ON match_utenti(annuncio_id);
CREATE TABLE messaggi_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mittente_id INTEGER NOT NULL,
        destinatario_id INTEGER NOT NULL,
        testo TEXT,
        ciphertext TEXT,
        nonce TEXT,
        eph_pub TEXT,
        eph_priv_enc TEXT,
        eph_priv_nonce TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        consegnato INTEGER DEFAULT 0,
        letto INTEGER DEFAULT 0,
        visibile_destinatario INTEGER DEFAULT 1,
        chat_chiusa INTEGER DEFAULT 0,
        FOREIGN KEY (mittente_id) REFERENCES utenti(id),
        FOREIGN KEY (destinatario_id) REFERENCES utenti(id)
    );
CREATE INDEX idx_chat_mitt_dest ON messaggi_chat(mittente_id, destinatario_id);
CREATE TABLE recensioni (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_autore INTEGER NOT NULL,
        id_destinatario INTEGER NOT NULL,
        voto INTEGER NOT NULL CHECK(voto BETWEEN 1 AND 5),
        testo TEXT,
        stato TEXT DEFAULT 'in_attesa',
        data TEXT DEFAULT (datetime('now')),
        ultima_modifica TEXT,
        FOREIGN KEY (id_autore) REFERENCES utenti(id),
        FOREIGN KEY (id_destinatario) REFERENCES utenti(id),
        CONSTRAINT univoco_autore_dest UNIQUE (id_autore, id_destinatario)
    );
CREATE TABLE risposte_recensioni (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_recensione INTEGER NOT NULL,
        id_autore INTEGER NOT NULL,
        testo TEXT NOT NULL,
        stato TEXT DEFAULT 'in_attesa',
        data TEXT DEFAULT (datetime('now')),
        ultima_modifica TEXT,
        FOREIGN KEY (id_recensione) REFERENCES recensioni(id) ON DELETE CASCADE,
        FOREIGN KEY (id_autore) REFERENCES utenti(id)
    );
CREATE TABLE notifiche (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_utente INTEGER NOT NULL,

        titolo TEXT,                  -- 🆕 titolo notifica
        messaggio TEXT NOT NULL,
        link TEXT,

        tipo TEXT DEFAULT 'generica', -- tipo notifica

        letta INTEGER DEFAULT 0,
        data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        data_lettura TIMESTAMP,
        scadenza_giorni INTEGER DEFAULT 10,

        FOREIGN KEY (id_utente) REFERENCES utenti(id)
    );
CREATE TABLE notifiche_admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titolo TEXT NOT NULL,
        messaggio TEXT NOT NULL,
        link TEXT,
        tipo_invio TEXT NOT NULL,
        tab_attivo TEXT NOT NULL,
        filtro_json TEXT NOT NULL,
        destinatari_count INTEGER NOT NULL,
        destinatari_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
CREATE TABLE password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        utente_id INTEGER NOT NULL,
        token TEXT NOT NULL UNIQUE,
        scadenza INTEGER NOT NULL,
        usato INTEGER DEFAULT 0,
        FOREIGN KEY (utente_id) REFERENCES utenti(id)
    );
CREATE TABLE chat_chiusure (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        closed_at TEXT NOT NULL,
        FOREIGN KEY (admin_id) REFERENCES utenti(id),
        FOREIGN KEY (user_id) REFERENCES utenti(id)
    );
CREATE TABLE segnalazioni_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        messaggio_id INTEGER NOT NULL,
        segnalato_da INTEGER NOT NULL,
        motivo TEXT,
        stato TEXT DEFAULT 'aperta',
        gestita_da INTEGER,
        data_gestione TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (messaggio_id) REFERENCES messaggi_chat(id),
        FOREIGN KEY (segnalato_da) REFERENCES utenti(id),
        FOREIGN KEY (gestita_da) REFERENCES utenti(id)
    );
CREATE INDEX idx_segnalazioni_messaggio
        ON segnalazioni_chat(messaggio_id);
CREATE TABLE video_call_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_name TEXT NOT NULL,
        utente_1 INTEGER NOT NULL,
        utente_2 INTEGER NOT NULL,

        created_at TEXT DEFAULT (datetime('now')),   -- inizio call
        ended_at TEXT,                               -- fine call

        durata_secondi INTEGER DEFAULT 0,

        -- minuti reali Daily già calcolati (participant-minutes)
        participant_minutes INTEGER DEFAULT 0,

        -- costo reale in centesimi
        costo_stimato_cent INTEGER DEFAULT 0,

        in_corso INTEGER DEFAULT 1,
        last_ping TEXT,

        FOREIGN KEY (utente_1) REFERENCES utenti(id),
        FOREIGN KEY (utente_2) REFERENCES utenti(id)
    );
CREATE INDEX idx_video_call_created
        ON video_call_log(created_at);
CREATE TABLE video_limiti_mensili (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mese TEXT NOT NULL,              -- formato YYYY-MM
        minuti_totali INTEGER DEFAULT 0,
        costo_totale_cent INTEGER DEFAULT 0,
        bloccato INTEGER DEFAULT 0,
        UNIQUE(mese)
    );
CREATE TABLE video_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        budget_mensile_cent INTEGER NOT NULL DEFAULT 2000,
        attivo INTEGER DEFAULT 1,
        updated_at TEXT DEFAULT (datetime('now'))
    );
CREATE TABLE servizi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        codice TEXT UNIQUE NOT NULL,
        nome TEXT NOT NULL,
        descrizione TEXT,
        ambito TEXT NOT NULL,
        target TEXT NOT NULL,
        durata_default_giorni INTEGER,
        ripetibile INTEGER DEFAULT 1,
        attivabile_admin INTEGER DEFAULT 1,
        attivo INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    );
CREATE TABLE servizi_piani (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        servizio_id INTEGER NOT NULL,

        codice TEXT NOT NULL,
        nome TEXT NOT NULL,
        descrizione TEXT,

        durata_giorni INTEGER NULL,
        prezzo_cent INTEGER NOT NULL DEFAULT 0,

        ordine INTEGER NOT NULL DEFAULT 1,

        evidenziato INTEGER NOT NULL DEFAULT 0,
        consigliato INTEGER NOT NULL DEFAULT 0,

        attivo INTEGER NOT NULL DEFAULT 1,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (servizio_id)
            REFERENCES servizi(id)
            ON DELETE CASCADE,

        UNIQUE(servizio_id, codice)
    );
CREATE TABLE pacchetti (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      codice TEXT UNIQUE NOT NULL,
      nome TEXT NOT NULL,
      descrizione TEXT,
      attivo INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    );
CREATE TABLE pacchetti_piani (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        pacchetto_id INTEGER NOT NULL,

        codice TEXT NOT NULL,
        nome TEXT NOT NULL,
        descrizione TEXT,

        durata_giorni INTEGER NULL,      -- NULL = permanente
        prezzo_cent INTEGER NOT NULL DEFAULT 0,

        ordine INTEGER NOT NULL DEFAULT 1,

        evidenziato INTEGER NOT NULL DEFAULT 0,
        consigliato INTEGER NOT NULL DEFAULT 0,

        attivo INTEGER NOT NULL DEFAULT 1,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (pacchetto_id)
            REFERENCES pacchetti(id)
            ON DELETE CASCADE,

        UNIQUE(pacchetto_id, codice)
    );
CREATE TABLE pacchetti_servizi (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pacchetto_id INTEGER NOT NULL,
      servizio_id INTEGER NOT NULL,

      -- ⏱ override opzionale durata servizio nel pacchetto
      durata_override INTEGER,

      created_at TEXT DEFAULT (datetime('now')),

      UNIQUE(pacchetto_id, servizio_id),
      FOREIGN KEY (pacchetto_id) REFERENCES pacchetti(id),
      FOREIGN KEY (servizio_id) REFERENCES servizi(id)
    );
CREATE TABLE prezzi (
      id INTEGER PRIMARY KEY AUTOINCREMENT,

      tipo TEXT NOT NULL CHECK(tipo IN ('servizio','pacchetto')),
      ref_id INTEGER NOT NULL,

      durata_giorni INTEGER,
      prezzo_cent INTEGER NOT NULL,
      valuta TEXT DEFAULT 'EUR',

      attivo INTEGER DEFAULT 1,
      ordine INTEGER DEFAULT 0,

      stripe_price_id TEXT,
      paypal_plan_id TEXT,

      created_at TEXT DEFAULT (datetime('now')),

      UNIQUE(tipo, ref_id, durata_giorni)
    );
CREATE TABLE acquisti (
      id INTEGER PRIMARY KEY AUTOINCREMENT,

      utente_id INTEGER NOT NULL,

      tipo TEXT NOT NULL CHECK(tipo IN ('servizio','pacchetto')),
      ref_id INTEGER NOT NULL,
      prezzo_id INTEGER,

      annuncio_id INTEGER,            -- 🆕 ANNUNCIO COLLEGATO (se presente)

      metodo TEXT NOT NULL,
      importo_cent INTEGER DEFAULT 0,
      valuta TEXT DEFAULT 'EUR',

      stato TEXT DEFAULT 'creato',
      riferimento_esterno TEXT,

      created_at TEXT DEFAULT (datetime('now')),

      FOREIGN KEY (utente_id) REFERENCES utenti(id),
      FOREIGN KEY (prezzo_id) REFERENCES prezzi(id),
      FOREIGN KEY (annuncio_id) REFERENCES annunci(id)
    );
CREATE INDEX idx_acquisti_utente
        ON acquisti(utente_id);
CREATE INDEX idx_acquisti_tipo_ref
        ON acquisti(tipo, ref_id);
CREATE INDEX idx_acquisti_annuncio
        ON acquisti(annuncio_id);
CREATE UNIQUE INDEX idx_acquisti_stripe_intent
        ON acquisti(riferimento_esterno)
        WHERE riferimento_esterno IS NOT NULL;
CREATE TABLE acquisti_servizi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        utente_id INTEGER NOT NULL,
        servizio_id INTEGER NOT NULL,
        metodo TEXT,
        importo REAL,
        valuta TEXT,
        riferimento_esterno TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (utente_id) REFERENCES utenti(id),
        FOREIGN KEY (servizio_id) REFERENCES servizi(id)
    );
CREATE TABLE attivazioni_servizi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        acquisto_id INTEGER,   -- riferimento a acquisti.id
        servizio_id INTEGER NOT NULL,
        utente_id INTEGER NOT NULL,
        annuncio_id INTEGER,

        data_inizio TEXT NOT NULL,
        data_fine TEXT,

        stato TEXT DEFAULT 'attivo',
        attivato_da TEXT DEFAULT 'utente',

        created_at TEXT DEFAULT (datetime('now')),

        FOREIGN KEY (acquisto_id) REFERENCES acquisti(id),
        FOREIGN KEY (servizio_id) REFERENCES servizi(id),
        FOREIGN KEY (utente_id) REFERENCES utenti(id),
        FOREIGN KEY (annuncio_id) REFERENCES annunci(id)
    );
CREATE INDEX idx_attivazioni_acquisto
        ON attivazioni_servizi(acquisto_id);
CREATE TABLE storico_servizi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attivazione_id INTEGER NOT NULL,
        azione TEXT NOT NULL,
        eseguito_da TEXT NOT NULL,
        note TEXT,
        data TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (attivazione_id) REFERENCES attivazioni_servizi(id)
    );
CREATE TABLE override_admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        servizio_id INTEGER NOT NULL,
        utente_id INTEGER NOT NULL,
        annuncio_id INTEGER,
        data_inizio TEXT NOT NULL,
        data_fine TEXT,
        motivo TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (admin_id) REFERENCES utenti(id),
        FOREIGN KEY (servizio_id) REFERENCES servizi(id),
        FOREIGN KEY (utente_id) REFERENCES utenti(id),
        FOREIGN KEY (annuncio_id) REFERENCES annunci(id)
    );
