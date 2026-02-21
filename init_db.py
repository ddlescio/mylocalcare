from app import get_db_connection, sql, IS_POSTGRES, now_sql
# =========================================================
# INIZIALIZZAZIONE DATABASE LOCALE - LocalCare (2025)
# =========================================================

def get_conn():
    return get_db_connection()
# ---------------------------------------------------------
# 🧩 TABELLA UTENTI
# ---------------------------------------------------------
def crea_tabella_utenti():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS utenti (
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
        data_creazione TEXT DEFAULT """ + now_sql() + """,

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
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'utenti' creata o aggiornata correttamente.")

# ---------------------------------------------------------
# 👥 TABELLA OPERATORI
# ---------------------------------------------------------
def crea_tabella_operatori():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS operatori (
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
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'operatori' pronta.")


# ---------------------------------------------------------
# 📢 TABELLA ANNUNCI
# ---------------------------------------------------------
def crea_tabella_annunci():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS annunci (
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
        data_pubblicazione TEXT DEFAULT """ + now_sql() + """,
        stato TEXT DEFAULT 'in_attesa',
        urgente INTEGER DEFAULT 0,
        approvato_il TEXT,
        match_da_processare INTEGER DEFAULT 0,
        ultima_notifica_urgente TEXT,
        FOREIGN KEY (utente_id) REFERENCES utenti(id)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'annunci' pronta.")

def crea_indici_annunci():
    conn = get_conn()
    c = conn.cursor()

    c.execute(sql("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_ad_per_category
        ON annunci(utente_id, categoria)
        WHERE stato IN ('in_attesa', 'approvato');
    """))

    conn.commit()
    conn.close()
    print("✅ Indice unico annunci per categoria creato.")

def crea_tabella_match_utenti():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS match_utenti (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        -- chi cerca e chi offre
        utente_cerca_id INTEGER NOT NULL,
        utente_offre_id INTEGER NOT NULL,

        categoria TEXT NOT NULL,
        zona TEXT,

        -- annuncio che ha generato il match (di solito quello “nuovo approvato”)
        annuncio_id INTEGER NOT NULL,

        created_at TEXT DEFAULT """ + now_sql() + """,
        notificato INTEGER DEFAULT 0,

        FOREIGN KEY (utente_cerca_id) REFERENCES utenti(id),
        FOREIGN KEY (utente_offre_id) REFERENCES utenti(id),
        FOREIGN KEY (annuncio_id) REFERENCES annunci(id),

        -- evita duplicati identici (stesso annuncio, stessi due utenti)
        UNIQUE (utente_cerca_id, utente_offre_id, annuncio_id)
    );
    """))
    c.execute("CREATE INDEX IF NOT EXISTS idx_match_cerca ON match_utenti(utente_cerca_id, notificato)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_match_annuncio ON match_utenti(annuncio_id)")
    conn.commit()
    conn.close()
    print("✅ Tabella 'match_utenti' pronta.")


# ---------------------------------------------------------
# 💬 TABELLA MESSAGGI CHAT
# ---------------------------------------------------------
def crea_tabella_messaggi_chat():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS messaggi_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mittente_id INTEGER NOT NULL,
        destinatario_id INTEGER NOT NULL,
        testo TEXT,
        ciphertext TEXT,
        nonce TEXT,
        eph_pub TEXT,
        eph_priv_enc TEXT,
        eph_priv_nonce TEXT,
        created_at TEXT DEFAULT """ + now_sql() + """,
        consegnato INTEGER DEFAULT 0,
        letto INTEGER DEFAULT 0,
        visibile_destinatario INTEGER DEFAULT 1,
        chat_chiusa INTEGER DEFAULT 0,
        FOREIGN KEY (mittente_id) REFERENCES utenti(id),
        FOREIGN KEY (destinatario_id) REFERENCES utenti(id)
    );
    """))
    c.execute("CREATE INDEX IF NOT EXISTS idx_chat_mitt_dest ON messaggi_chat(mittente_id, destinatario_id)")
    conn.commit()
    conn.close()
    print("✅ Tabella 'messaggi_chat' pronta.")

def crea_tabella_chat_chiusure():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS chat_chiusure (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        closed_at TEXT NOT NULL,
        FOREIGN KEY (admin_id) REFERENCES utenti(id),
        FOREIGN KEY (user_id) REFERENCES utenti(id)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'chat_chiusure' pronta.")

# ---------------------------------------------------------
# 🚨 TABELLA SEGNALAZIONI CHAT
# ---------------------------------------------------------
def crea_tabella_segnalazioni_chat():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS segnalazioni_chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        messaggio_id INTEGER NOT NULL,
        segnalato_da INTEGER NOT NULL,
        motivo TEXT,
        stato TEXT DEFAULT 'aperta',
        gestita_da INTEGER,
        data_gestione TEXT,
        created_at TEXT DEFAULT """ + now_sql() + """,
        FOREIGN KEY (messaggio_id) REFERENCES messaggi_chat(id),
        FOREIGN KEY (segnalato_da) REFERENCES utenti(id),
        FOREIGN KEY (gestita_da) REFERENCES utenti(id)
    );
    """))
    c.execute(sql("""
        CREATE INDEX IF NOT EXISTS idx_segnalazioni_messaggio
        ON segnalazioni_chat(messaggio_id);
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'segnalazioni_chat' pronta.")

# ---------------------------------------------------------
# 📹 LOG VIDEOCHIAMATE
# ---------------------------------------------------------
def crea_tabella_video_call_log():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS video_call_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_name TEXT NOT NULL,
        utente_1 INTEGER NOT NULL,
        utente_2 INTEGER NOT NULL,

        created_at TEXT DEFAULT """ + now_sql() + """,   -- inizio call
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
    """))
    c.execute(sql("""
        CREATE INDEX IF NOT EXISTS idx_video_call_created
        ON video_call_log(created_at);
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'video_call_log' pronta.")

# ---------------------------------------------------------
# 📊 LIMITI MENSILI VIDEO
# ---------------------------------------------------------
def crea_tabella_video_limiti_mensili():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS video_limiti_mensili (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mese TEXT NOT NULL,              -- formato YYYY-MM
        minuti_totali INTEGER DEFAULT 0,
        costo_totale_cent INTEGER DEFAULT 0,
        bloccato INTEGER DEFAULT 0,
        UNIQUE(mese)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'video_limiti_mensili' pronta.")

# ---------------------------------------------------------
# ⚙️ CONFIGURAZIONE VIDEO (budget globale)
# ---------------------------------------------------------
def crea_tabella_video_config():
    conn = get_conn()
    c = conn.cursor()

    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS video_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        budget_mensile_cent INTEGER NOT NULL DEFAULT 2000,
        attivo INTEGER DEFAULT 1,
        updated_at TEXT DEFAULT """ + now_sql() + """
    );
    """))

    # Garantiamo che esista sempre UNA SOLA riga
    c.execute("SELECT COUNT(*) FROM video_config")
    count = c.fetchone()[0]

    if count == 0:
        c.execute(sql("""
            INSERT INTO video_config (budget_mensile_cent, attivo)
            VALUES (2000, 1)
        """))
        print("✅ video_config inizializzato con budget 20€.")

    conn.commit()
    conn.close()
    print("✅ Tabella 'video_config' pronta.")

# ---------------------------------------------------------
# ⭐ TABELLA RECENSIONI
# ---------------------------------------------------------
def crea_tabella_recensioni():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS recensioni (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_autore INTEGER NOT NULL,
        id_destinatario INTEGER NOT NULL,
        voto INTEGER NOT NULL CHECK(voto BETWEEN 1 AND 5),
        testo TEXT,
        stato TEXT DEFAULT 'in_attesa',
        data TEXT DEFAULT """ + now_sql() + """,
        ultima_modifica TEXT,
        FOREIGN KEY (id_autore) REFERENCES utenti(id),
        FOREIGN KEY (id_destinatario) REFERENCES utenti(id),
        CONSTRAINT univoco_autore_dest UNIQUE (id_autore, id_destinatario)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'recensioni' pronta.")


# ---------------------------------------------------------
# 💬 TABELLA RISPOSTE ALLE RECENSIONI
# ---------------------------------------------------------
def crea_tabella_risposte():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS risposte_recensioni (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        id_recensione INTEGER NOT NULL,
        id_autore INTEGER NOT NULL,
        testo TEXT NOT NULL,
        stato TEXT DEFAULT 'in_attesa',
        data TEXT DEFAULT """ + now_sql() + """,
        ultima_modifica TEXT,
        FOREIGN KEY (id_recensione) REFERENCES recensioni(id) ON DELETE CASCADE,
        FOREIGN KEY (id_autore) REFERENCES utenti(id)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'risposte_recensioni' pronta.")


# ---------------------------------------------------------
# 🔔 TABELLA NOTIFICHE
# ---------------------------------------------------------
def crea_tabella_notifiche():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS notifiche (
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
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'notifiche' pronta.")

# ---------------------------------------------------------
# 🗂️ TABELLA NOTIFICHE INVIATE DALL'ADMIN
# ---------------------------------------------------------
def crea_tabella_notifiche_admin():
    conn = get_conn()
    c = conn.cursor()

    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS notifiche_admin (
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
    """))

    conn.commit()
    conn.close()
    print("✅ Tabella 'notifiche_admin' pronta.")

# ---------------------------------------------------------
# 🔑 TABELLA RESET PASSWORD
# ---------------------------------------------------------
def crea_tabella_reset_password():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        utente_id INTEGER NOT NULL,
        token TEXT NOT NULL UNIQUE,
        scadenza INTEGER NOT NULL,
        usato INTEGER DEFAULT 0,
        FOREIGN KEY (utente_id) REFERENCES utenti(id)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'password_reset_tokens' pronta.")

# ---------------------------------------------------------
# 💳 TABELLA SERVIZI (catalogo)
# ---------------------------------------------------------
def crea_tabella_servizi():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS servizi (
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
        created_at TEXT DEFAULT """ + now_sql() + """
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'servizi' pronta.")

# ---------------------------------------------------------
# 💳 TABELLA SERVIZI_PIANI (piani di prezzo per servizio)
# ---------------------------------------------------------
def crea_tabella_servizi_piani():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS servizi_piani (
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
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'servizi_piani' pronta.")

# ---------------------------------------------------------
# 💳 TABELLA PACCHETTI_PIANI (piani di prezzo per pacchetti)
# ---------------------------------------------------------

def crea_tabella_pacchetti():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS pacchetti (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      codice TEXT UNIQUE NOT NULL,
      nome TEXT NOT NULL,
      descrizione TEXT,
      attivo INTEGER DEFAULT 1,
      created_at TEXT DEFAULT """ + now_sql() + """
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'pacchetti' pronta.")

def crea_tabella_pacchetti_piani():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS pacchetti_piani (
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
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'pacchetti_piani' pronta.")


def crea_tabella_pacchetti_servizi():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS pacchetti_servizi (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pacchetto_id INTEGER NOT NULL,
      servizio_id INTEGER NOT NULL,

      -- ⏱ override opzionale durata servizio nel pacchetto
      durata_override INTEGER,

      created_at TEXT DEFAULT """ + now_sql() + """,

      UNIQUE(pacchetto_id, servizio_id),
      FOREIGN KEY (pacchetto_id) REFERENCES pacchetti(id),
      FOREIGN KEY (servizio_id) REFERENCES servizi(id)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'pacchetti_servizi' pronta (con durata_override).")

def crea_tabella_prezzi():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS prezzi (
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

      created_at TEXT DEFAULT """ + now_sql() + """,

      UNIQUE(tipo, ref_id, durata_giorni)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'prezzi' pronta.")

def crea_tabella_acquisti():
    conn = get_conn()
    c = conn.cursor()

    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS acquisti (
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

      created_at TEXT DEFAULT """ + now_sql() + """,

      FOREIGN KEY (utente_id) REFERENCES utenti(id),
      FOREIGN KEY (prezzo_id) REFERENCES prezzi(id),
      FOREIGN KEY (annuncio_id) REFERENCES annunci(id)
    );
    """))

    # indici standard
    c.execute(sql("""
        CREATE INDEX IF NOT EXISTS idx_acquisti_utente
        ON acquisti(utente_id);
    """))

    c.execute(sql("""
        CREATE INDEX IF NOT EXISTS idx_acquisti_tipo_ref
        ON acquisti(tipo, ref_id);
    """))

    c.execute(sql("""
        CREATE INDEX IF NOT EXISTS idx_acquisti_annuncio
        ON acquisti(annuncio_id);
    """))

    # 🔐 indice CRITICO per Stripe (idempotenza)
    c.execute(sql("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_acquisti_stripe_intent
        ON acquisti(riferimento_esterno)
        WHERE riferimento_esterno IS NOT NULL;
    """))

    conn.commit()
    conn.close()
    print("✅ Tabella 'acquisti' pronta (con annuncio_id).")

def crea_tabella_acquisti_servizi():
    conn = get_conn()
    c = conn.cursor()

    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS acquisti_servizi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        utente_id INTEGER NOT NULL,
        servizio_id INTEGER NOT NULL,
        metodo TEXT,
        importo REAL,
        valuta TEXT,
        riferimento_esterno TEXT,
        created_at TEXT DEFAULT """ + now_sql() + """,
        FOREIGN KEY (utente_id) REFERENCES utenti(id),
        FOREIGN KEY (servizio_id) REFERENCES servizi(id)
    );
    """))

    conn.commit()
    conn.close()
    print("✅ Tabella 'acquisti_servizi' pronta.")

# ---------------------------------------------------------
# ✅ TABELLA ATTIVAZIONI SERVIZI (cosa è attivo ORA)
# ---------------------------------------------------------
def crea_tabella_attivazioni_servizi():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS attivazioni_servizi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        acquisto_id INTEGER,   -- riferimento a acquisti.id
        servizio_id INTEGER NOT NULL,
        utente_id INTEGER NOT NULL,
        annuncio_id INTEGER,

        data_inizio TEXT NOT NULL,
        data_fine TEXT,

        stato TEXT DEFAULT 'attivo',
        attivato_da TEXT DEFAULT 'utente',

        created_at TEXT DEFAULT """ + now_sql() + """,

        FOREIGN KEY (acquisto_id) REFERENCES acquisti(id),
        FOREIGN KEY (servizio_id) REFERENCES servizi(id),
        FOREIGN KEY (utente_id) REFERENCES utenti(id),
        FOREIGN KEY (annuncio_id) REFERENCES annunci(id)
    );
    """))

    c.execute(sql("""
        CREATE INDEX IF NOT EXISTS idx_attivazioni_acquisto
        ON attivazioni_servizi(acquisto_id);
    """))

    conn.commit()
    conn.close()
    print("✅ Tabella 'attivazioni_servizi' pronta (schema definitivo).")

# ---------------------------------------------------------
# 🧾 TABELLA STORICO SERVIZI (audit log)
# ---------------------------------------------------------
def crea_tabella_storico_servizi():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS storico_servizi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attivazione_id INTEGER NOT NULL,
        azione TEXT NOT NULL,
        eseguito_da TEXT NOT NULL,
        note TEXT,
        data TEXT DEFAULT """ + now_sql() + """,
        FOREIGN KEY (attivazione_id) REFERENCES attivazioni_servizi(id)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'storico_servizi' pronta.")


# ---------------------------------------------------------
# 🛠️ TABELLA OVERRIDE ADMIN (attivazioni manuali)
# ---------------------------------------------------------
def crea_tabella_override_admin():
    conn = get_conn()
    c = conn.cursor()
    c.execute(sql("""
    CREATE TABLE IF NOT EXISTS override_admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        servizio_id INTEGER NOT NULL,
        utente_id INTEGER NOT NULL,
        annuncio_id INTEGER,
        data_inizio TEXT NOT NULL,
        data_fine TEXT,
        motivo TEXT,
        created_at TEXT DEFAULT """ + now_sql() + """,
        FOREIGN KEY (admin_id) REFERENCES utenti(id),
        FOREIGN KEY (servizio_id) REFERENCES servizi(id),
        FOREIGN KEY (utente_id) REFERENCES utenti(id),
        FOREIGN KEY (annuncio_id) REFERENCES annunci(id)
    );
    """))
    conn.commit()
    conn.close()
    print("✅ Tabella 'override_admin' pronta.")


# ---------------------------------------------------------
# 🧱 AGGIORNA COLONNE MANCANTI (no perdita dati)
# ---------------------------------------------------------
def aggiorna_colonne_mancanti():
    conn = get_conn()
    c = conn.cursor()

    c.execute("PRAGMA table_info(utenti)")
    colonne_utenti = [row[1] for row in c.fetchall()]

    colonne_da_aggiungere = {

        # 📍 Posizione geografica
        "macro_area": "TEXT",
        "provincia": "TEXT",
        "regione": "TEXT",

        # 🆕 Gestione account
        "ruolo": "TEXT DEFAULT 'user'",
        # Info base / testo profilo
        "frase": "TEXT",
        "lingue": "TEXT",
        "descrizione": "TEXT",
        "esperienza_1": "TEXT",
        "esperienza_2": "TEXT",
        "esperienza_3": "TEXT",
        "studio_1": "TEXT",
        "studio_2": "TEXT",
        "studio_3": "TEXT",
        "certificazioni": "TEXT",
        "sito_web": "TEXT",
        "instagram": "TEXT",
        "facebook": "TEXT",
        "linkedin": "TEXT",
        "orari": "TEXT",
        "preferenze_contatto": "TEXT",
        "offro_9": "INTEGER DEFAULT 0",
        "offro_10": "INTEGER DEFAULT 0",
        "cerco_9": "INTEGER DEFAULT 0",
        "cerco_10": "INTEGER DEFAULT 0",

        # Visibilità / stato account
        "visibile_pubblicamente": "INTEGER DEFAULT 1",
        "visibile_in_chat": "INTEGER DEFAULT 1",
        "sospeso": "INTEGER DEFAULT 0",
        "disattivato_admin": "INTEGER DEFAULT 0",
        "email_notifiche": "INTEGER DEFAULT 1",

        # Recensioni e tracking
        "media_recensioni": "REAL DEFAULT 0",
        "numero_recensioni": "INTEGER DEFAULT 0",
        "data_creazione": "TEXT DEFAULT """ + now_sql() + """",
        "foto_galleria": "TEXT",

        # Cifratura (DEK + ID + X25519)
        "key_salt": "TEXT",
        "dek_enc": "TEXT",
        "dek_nonce": "TEXT",
        "dek_mk_enc": "TEXT",
        "dek_mk_nonce": "TEXT",
        "id_pub": "TEXT",
        "id_priv_enc": "TEXT",
        "id_priv_nonce": "TEXT",
        "x25519_pub": "TEXT",
        "x25519_priv_enc": "TEXT",
        "x25519_priv_nonce": "TEXT",

        # 🔐 Sicurezza login/admin
        "failed_logins": "INTEGER DEFAULT 0",
        "lock_until": "TEXT",
        "admin_session_token": "TEXT",
        "admin_session_expiry": "TEXT",
        "admin_browser_fingerprint": "TEXT",
    }

    for col, tipo in colonne_da_aggiungere.items():
        if col not in colonne_utenti:
            c.execute(f"ALTER TABLE utenti ADD COLUMN {col} {tipo};")
            print(f"✅ Colonna '{col}' aggiunta alla tabella utenti.")

    # ---------------------------------------------------------
    # 💬 Aggiornamento colonne MESSAGGI_CHAT
    # ---------------------------------------------------------
    c.execute("PRAGMA table_info(messaggi_chat)")
    colonne_chat = [row[1] for row in c.fetchall()]

    if "chat_chiusa" not in colonne_chat:
        c.execute(sql("""
            ALTER TABLE messaggi_chat
            ADD COLUMN chat_chiusa INTEGER DEFAULT 0;
        """))
        print("✅ Colonna 'chat_chiusa' aggiunta a messaggi_chat.")
    # ---------------------------------------------------------
    # 🔔 AGGIORNAMENTO COLONNE NOTIFICHE
    # ---------------------------------------------------------
    c.execute("PRAGMA table_info(notifiche)")
    colonne_notifiche = [row[1] for row in c.fetchall()]

    if "titolo" not in colonne_notifiche:
        c.execute("ALTER TABLE notifiche ADD COLUMN titolo TEXT;")
        print("✅ Colonna 'titolo' aggiunta a notifiche.")

    if "tipo" not in colonne_notifiche:
        c.execute("ALTER TABLE notifiche ADD COLUMN tipo TEXT DEFAULT 'generica';")
        print("✅ Colonna 'tipo' aggiunta a notifiche.")

    # ---------------------------------------------------------
    # 📢 Aggiornamento colonne ANNUNCI
    # ---------------------------------------------------------
    c.execute("PRAGMA table_info(annunci)")
    colonne_annunci = [row[1] for row in c.fetchall()]

    if "provincia" not in colonne_annunci:
        c.execute("ALTER TABLE annunci ADD COLUMN provincia TEXT;")
        print("✅ Colonna 'provincia' aggiunta a annunci.")

    if "approvato_il" not in colonne_annunci:
        c.execute("ALTER TABLE annunci ADD COLUMN approvato_il TEXT;")
        print("✅ Colonna 'approvato_il' aggiunta a annunci.")

    if "match_da_processare" not in colonne_annunci:
        c.execute("ALTER TABLE annunci ADD COLUMN match_da_processare INTEGER DEFAULT 0;")
        print("✅ Colonna 'match_da_processare' aggiunta a annunci.")

    if "tipo_annuncio" not in colonne_annunci:
        c.execute(sql("""
            ALTER TABLE annunci
            ADD COLUMN tipo_annuncio TEXT
            CHECK (tipo_annuncio IN ('offro','cerco'));
        """))
        print("✅ Colonna 'tipo_annuncio' aggiunta a annunci.")

    if "urgente" not in colonne_annunci:
        c.execute(sql("""
            ALTER TABLE annunci
            ADD COLUMN urgente INTEGER DEFAULT 0;
        """))
        print("✅ Colonna 'urgente' aggiunta a annunci.")

        # indice utile per ordinamenti/filtri
        c.execute(sql("""
            CREATE INDEX IF NOT EXISTS idx_annunci_urgente
            ON annunci(urgente);
        """))
        print("✅ Indice 'idx_annunci_urgente' creato.")

    if "ultima_notifica_urgente" not in colonne_annunci:
        c.execute(sql("""
            ALTER TABLE annunci
            ADD COLUMN ultima_notifica_urgente TEXT;
        """))
        print("✅ Colonna 'ultima_notifica_urgente' aggiunta a annunci.")

        c.execute(sql("""
            CREATE INDEX IF NOT EXISTS idx_annunci_ultima_notifica_urgente
            ON annunci(ultima_notifica_urgente);
        """))
        print("✅ Indice 'idx_annunci_ultima_notifica_urgente' creato.")

    # ---------------------------------------------------------
    # 🗂️ AGGIORNAMENTO TABELLA NOTIFICHE_ADMIN
    # ---------------------------------------------------------
    c.execute(sql("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='notifiche_admin'
    """))
    if c.fetchone():
        c.execute("PRAGMA table_info(notifiche_admin)")
        colonne_admin = [row[1] for row in c.fetchall()]

        if "destinatari_json" not in colonne_admin:
            c.execute(sql("""
                ALTER TABLE notifiche_admin
                ADD COLUMN destinatari_json TEXT;
            """))
            print("✅ Colonna 'destinatari_json' aggiunta a notifiche_admin.")

    # ---------------------------------------------------------
    # 📹 AGGIORNAMENTO VIDEO CALL LOG
    # ---------------------------------------------------------
    c.execute("PRAGMA table_info(video_call_log)")
    colonne_video = [row[1] for row in c.fetchall()]

    if "in_corso" not in colonne_video:
        c.execute(sql("""
            ALTER TABLE video_call_log
            ADD COLUMN in_corso INTEGER DEFAULT 1;
        """))
        print("✅ Colonna 'in_corso' aggiunta a video_call_log.")

    # ---------------------------------------------------------
    # Salvataggio modifiche
    # ---------------------------------------------------------
    conn.commit()
    conn.close()

# ---------------------------------------------------------
# 🚀 INIZIALIZZAZIONE COMPLETA
# ---------------------------------------------------------
def inizializza_database():
    print("🔧 Creazione e aggiornamento database LocalCare...")

    crea_tabella_utenti()
    crea_tabella_operatori()
    crea_tabella_annunci()
    crea_indici_annunci()

    crea_tabella_match_utenti()
    crea_tabella_messaggi_chat()
    crea_tabella_recensioni()
    crea_tabella_risposte()
    crea_tabella_notifiche()
    crea_tabella_notifiche_admin()
    crea_tabella_reset_password()
    crea_tabella_chat_chiusure()
    crea_tabella_segnalazioni_chat()
    crea_tabella_video_call_log()
    crea_tabella_video_limiti_mensili()
    crea_tabella_video_config()

    # 💳 Monetizzazione / Boost / Vetrina / Contatti
    crea_tabella_servizi()
    crea_tabella_servizi_piani()
    crea_tabella_pacchetti()
    crea_tabella_pacchetti_piani()
    crea_tabella_pacchetti_servizi()
    crea_tabella_prezzi()
    crea_tabella_acquisti()
    crea_tabella_acquisti_servizi()
    crea_tabella_attivazioni_servizi()
    crea_tabella_storico_servizi()
    crea_tabella_override_admin()

    if not IS_POSTGRES:
        aggiorna_colonne_mancanti()

    print("✅ Tutte le tabelle create o aggiornate correttamente (senza perdita dati).")

def imposta_admin_predefinito():
    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE utenti SET ruolo = 'admin' WHERE id = 1")
    conn.commit()
    conn.close()
    print("👑 Utente #1 impostato come amministratore.")

# ---------------------------------------------------------
# ✅ ESECUZIONE DIRETTA
# ---------------------------------------------------------
if __name__ == "__main__":
    inizializza_database()
