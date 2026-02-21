# models.py

def get_db_connection():
    from app import get_db_connection as _get_db_connection
    return _get_db_connection()
# -----------------------------
# CHAT – FUNZIONI PRINCIPALI (aggiornate con consegnato/letto/orario)
# -----------------------------
import sqlite3
import base64
from flask import session
from Crypto.Cipher import AES
from nacl.public import PrivateKey, PublicKey
from flask_socketio import SocketIO

# ------------------------------------------------------
# Helper: ottiene la DEK decifrata (dalla sessione)
# ------------------------------------------------------
def _get_dek():
    dek_b64 = session.get("dek_b64")
    if not dek_b64:
        raise ValueError("Chiave DEK non presente in sessione (utente non autenticato correttamente)")
    return base64.b64decode(dek_b64)

def _derive_shared_key(x_priv_bytes: bytes, other_pub_b64: str) -> bytes:
    """Deriva una chiave condivisa (ECDH X25519) tra mittente e destinatario."""
    try:
        priv = PrivateKey(x_priv_bytes)
        other_pub = PublicKey(base64.b64decode(other_pub_b64))
        shared = priv.exchange(other_pub)  # 32 byte
        return shared
    except Exception as e:
        print("Errore nella derivazione ECDH:", e)
        raise

# ------------------------------------------------------
# CHAT – CIFRATURA E DECIFRATURA
# ------------------------------------------------------
def chat_invia(mittente_id: int, destinatario_id: int, testo: str):
    """Cifra il messaggio con ECDH (X25519) + AES-GCM e lo salva nel DB."""
    from nacl.public import Box

    # --- Recupera chiave privata X25519 del mittente ---
    x_priv_b64 = session.get("x25519_priv_b64")
    if not x_priv_b64:
        raise ValueError("Chiave privata X25519 mancante in sessione")

    x_priv_bytes = base64.b64decode(x_priv_b64)
    priv_mittente = PrivateKey(x_priv_bytes)

    # --- Recupera chiave pubblica del destinatario ---
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT x25519_pub FROM utenti WHERE id = ?", (destinatario_id,))
    row = c.fetchone()
    if not row or not row[0]:
        conn.close()
        raise ValueError("Destinatario senza chiave pubblica registrata")

    dest_pub_b64 = row[0]
    pub_dest = PublicKey(base64.b64decode(dest_pub_b64))

    # --- Genera chiave effimera e calcola chiave condivisa ---
    eph_priv = PrivateKey.generate()
    eph_pub = eph_priv.public_key

    # 🔹 Deriva chiave condivisa come mittente
    #    (Box con effimera privata + pubblica destinatario)
    box = Box(eph_priv, pub_dest)
    shared = box.shared_key()

    # --- Cifra testo con AES-GCM ---
    cipher = AES.new(shared, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(testo.encode())

    blob_b64 = base64.b64encode(ciphertext + tag).decode()
    nonce_b64 = base64.b64encode(cipher.nonce).decode()
    eph_pub_b64 = base64.b64encode(bytes(eph_pub)).decode()

    # --- 🔐 Cifra la chiave effimera privata con la DEK personale ---
    dek = base64.b64decode(session["dek_b64"])
    cipher_eph = AES.new(dek, AES.MODE_GCM)
    eph_ct, eph_tag = cipher_eph.encrypt_and_digest(bytes(eph_priv))
    eph_priv_enc_b64 = base64.b64encode(eph_ct + eph_tag).decode()
    eph_priv_nonce_b64 = base64.b64encode(cipher_eph.nonce).decode()

    # --- 💾 Salva nel DB (aggiunte le colonne per la chiave effimera cifrata) ---
    c.execute("""
        INSERT INTO messaggi_chat (
            mittente_id, destinatario_id, testo,
            ciphertext, nonce, eph_pub,
            eph_priv_enc, eph_priv_nonce,
            consegnato, letto
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
    """, (
        mittente_id, destinatario_id, "🔒",
        blob_b64, nonce_b64, eph_pub_b64,
        eph_priv_enc_b64, eph_priv_nonce_b64
    ))
    conn.commit()
    msg_id = c.lastrowid
    conn.close()
    return msg_id

def chat_conversazione(user_id: int, other_id: int, limit: int = 100, after_id: int | None = None):
    """Restituisce la conversazione decifrando i messaggi leggibili con la chiave privata X25519."""
    from nacl.public import Box

    conn = get_db_connection()

    c = conn.cursor()

    # 🔍 Recupera ruolo utente per capire se applicare il cutoff
    ruolo_row = c.execute("SELECT ruolo FROM utenti WHERE id = ?", (user_id,)).fetchone()
    ruolo = ruolo_row["ruolo"] if ruolo_row else None

    # 🔪 cutoff solo per NON admin
    cutoff = None
    if ruolo != "admin":
        row = c.execute("""
            SELECT closed_at
            FROM chat_chiusure
            WHERE admin_id = 1 AND user_id = ?
            ORDER BY closed_at DESC LIMIT 1
        """, (user_id,)).fetchone()
        cutoff = row["closed_at"] if row else None

    sql = """
        SELECT id, mittente_id, destinatario_id,
               testo, ciphertext, nonce, eph_pub,
               eph_priv_enc, eph_priv_nonce,
               created_at, consegnato, letto
        FROM messaggi_chat
        WHERE (
               (mittente_id = ? AND destinatario_id = ?)
            OR (mittente_id = ? AND destinatario_id = ?)
        )
        AND ( ? IS NULL OR created_at > ? )
        ORDER BY created_at DESC
        LIMIT ?
    """
    rows = c.execute(sql, [user_id, other_id, other_id, user_id, cutoff, cutoff, limit]).fetchall()
    conn.close()
    rows = list(reversed(rows))  # mostra dal più vecchio al più recente

    messaggi_decifrati = []
    x_priv_b64 = session.get("x25519_priv_b64")
    if not x_priv_b64:
        return [dict(r) for r in rows]

    priv = PrivateKey(base64.b64decode(x_priv_b64))
    dek = base64.b64decode(session["dek_b64"])

    for r in rows:
        r = dict(r)
        try:
            raw = base64.b64decode(r["ciphertext"])
            nonce = base64.b64decode(r["nonce"])
            ct, tag = raw[:-16], raw[-16:]

            # --- Se il messaggio è stato INVIATO da me ---
            if r["mittente_id"] == user_id:
                if not r.get("eph_priv_enc") or not r.get("eph_priv_nonce"):
                    raise ValueError("Chiave effimera privata mancante per messaggio inviato")

                # 🔹 Decifra la chiave effimera privata con la DEK
                eph_ct_raw = base64.b64decode(r["eph_priv_enc"])
                eph_nonce = base64.b64decode(r["eph_priv_nonce"])
                eph_ct, eph_tag = eph_ct_raw[:-16], eph_ct_raw[-16:]
                cipher_eph = AES.new(dek, AES.MODE_GCM, nonce=eph_nonce)
                eph_priv_bytes = cipher_eph.decrypt_and_verify(eph_ct, eph_tag)
                eph_priv = PrivateKey(eph_priv_bytes)

                # --- Recupera chiave pubblica del destinatario ---
                conn2 = get_db_connection()
                try:
                    c2 = conn2.cursor()
                    c2.execute("SELECT x25519_pub FROM utenti WHERE id = ?", (r["destinatario_id"],))
                    row_dest = c2.fetchone()
                    if not row_dest or not row_dest[0]:
                        raise ValueError("Destinatario senza chiave pubblica")
                    pub_dest = PublicKey(base64.b64decode(row_dest[0]))
                finally:
                    conn2.close()

                box = Box(eph_priv, pub_dest)
                shared = box.shared_key()

            else:
                # --- Sono il destinatario ---
                eph_pub = PublicKey(base64.b64decode(r["eph_pub"]))
                box = Box(priv, eph_pub)
                shared = box.shared_key()

            cipher = AES.new(shared, AES.MODE_GCM, nonce=nonce)
            r["testo"] = cipher.decrypt_and_verify(ct, tag).decode()

        except Exception as e:
            # evitiamo key error su 'altro_id' / 'ultimo_testo'
            print(f"[Errore decifrando messaggio chat {r.get('id')}] {e}")
            r["testo"] = "🔒 Messaggio cifrato"

        messaggi_decifrati.append(r)

    return messaggi_decifrati

def chat_threads(user_id: int):
    """
    Restituisce la lista delle chat con:
      - username/nome altro utente
      - ultimo messaggio (decifrato, se possibile)
      - mittente dell’ultimo messaggio
      - numero di non letti
    """
    from nacl.public import PrivateKey, PublicKey, Box
    from Crypto.Cipher import AES

    conn = get_db_connection()

    c = conn.cursor()

    # 🔍 Recupera ruolo utente (serve per capire se filtrare le chat chiuse)
    ruolo = c.execute("SELECT ruolo FROM utenti WHERE id = ?", (user_id,)).fetchone()
    ruolo = ruolo["ruolo"] if ruolo else None

    cutoff = None
    if ruolo != "admin":
        row = c.execute("""
            SELECT closed_at
            FROM chat_chiusure
            WHERE admin_id = 1 AND user_id = ?
            ORDER BY closed_at DESC LIMIT 1
        """, (user_id,)).fetchone()
        cutoff = row["closed_at"] if row else None

    # 🔥 Filtra chat chiuse se NON admin
    filtro_chat = ""
    if ruolo != "admin":
        filtro_chat = " AND chat_chiusa = 0 "

    rows = c.execute(f"""
        WITH all_msgs AS (
            SELECT
                CASE
                    WHEN mittente_id = ? THEN destinatario_id
                    ELSE mittente_id
                END AS altro_id,
                id,
                mittente_id,
                destinatario_id,
                ciphertext,
                nonce,
                eph_pub,
                eph_priv_enc,
                eph_priv_nonce,
                created_at,
                consegnato,
                letto
            FROM messaggi_chat
            WHERE (mittente_id = ? OR destinatario_id = ?)
            {filtro_chat}
            AND ( ? IS NULL OR created_at > ? )
        ),
        last_msg AS (
            SELECT
                altro_id,
                id AS ultimo_id,
                mittente_id AS ultimo_mittente_id,
                destinatario_id AS ultimo_destinatario_id,
                ciphertext AS ultimo_ciphertext,
                nonce AS ultimo_nonce,
                eph_pub AS ultimo_eph_pub,
                eph_priv_enc AS ultimo_eph_priv_enc,
                eph_priv_nonce AS ultimo_eph_priv_nonce,
                created_at AS ultimo_invio,
                consegnato AS ultimo_consegnato,
                letto AS ultimo_letto
            FROM (
                SELECT *,
                       ROW_NUMBER() OVER(
                           PARTITION BY altro_id
                           ORDER BY id DESC
                       ) AS rn
                FROM all_msgs
            ) t
            WHERE rn = 1
        )
        SELECT
            a.altro_id,
            u.username AS username_altro,
            u.nome AS altro_nome,
            u.cognome AS altro_cognome,
            u.foto_profilo AS altro_foto,
            lm.ultimo_id AS last_msg_id,
            lm.ultimo_mittente_id,
            lm.ultimo_destinatario_id,
            lm.ultimo_ciphertext,
            lm.ultimo_nonce,
            lm.ultimo_eph_pub,
            lm.ultimo_eph_priv_enc,
            lm.ultimo_eph_priv_nonce,
            lm.ultimo_invio,
            lm.ultimo_consegnato,
            lm.ultimo_letto,
            (
                SELECT COUNT(*)
                FROM all_msgs
                WHERE altro_id = a.altro_id
                  AND mittente_id = a.altro_id
                  AND letto = 0
            ) AS non_letti
        FROM all_msgs a
        JOIN utenti u ON u.id = a.altro_id
            AND u.sospeso = 0
            AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
            AND u.attivo = 1
        JOIN last_msg lm ON lm.altro_id = a.altro_id
        GROUP BY a.altro_id
        ORDER BY last_msg_id DESC;
    """, (user_id, user_id, user_id, cutoff, cutoff)).fetchall()

    conn.close()

    # 🔑 recupero chiavi dalla sessione (stessa logica di chat_conversazione)
    x_priv_b64 = session.get("x25519_priv_b64")
    dek_b64 = session.get("dek_b64")

    priv = None
    dek = None
    if x_priv_b64 and dek_b64:
        priv = PrivateKey(base64.b64decode(x_priv_b64))
        dek = base64.b64decode(dek_b64)

    threads = []

    for r in rows:
        d = dict(r)

        # username sempre presente
        d["altro_username"] = r["username_altro"]
        d["nome_chat"] = "@" + d["altro_username"]

        testo = "🔒 Messaggio cifrato"

        if priv is not None and dek is not None and r["ultimo_ciphertext"]:
            try:
                raw = base64.b64decode(r["ultimo_ciphertext"])
                nonce = base64.b64decode(r["ultimo_nonce"])
                ct, tag = raw[:-16], raw[-16:]

                if r["ultimo_mittente_id"] == user_id:
                    # 📨 messaggio INVIATO da me
                    eph_priv_enc_b64 = r["ultimo_eph_priv_enc"]
                    eph_priv_nonce_b64 = r["ultimo_eph_priv_nonce"]
                    if not eph_priv_enc_b64 or not eph_priv_nonce_b64:
                        raise ValueError("Chiave effimera privata mancante per messaggio inviato")

                    eph_ct_raw = base64.b64decode(eph_priv_enc_b64)
                    eph_nonce = base64.b64decode(eph_priv_nonce_b64)
                    eph_ct, eph_tag = eph_ct_raw[:-16], eph_ct_raw[-16:]

                    cipher_eph = AES.new(dek, AES.MODE_GCM, nonce=eph_nonce)
                    eph_priv_bytes = cipher_eph.decrypt_and_verify(eph_ct, eph_tag)
                    eph_priv = PrivateKey(eph_priv_bytes)

                    # chiave pubblica destinatario
                    conn2 = get_db_connection()
                    try:
                        c2 = conn2.cursor()
                        c2.execute("SELECT x25519_pub FROM utenti WHERE id = ?", (r["ultimo_destinatario_id"],))
                        row_dest = c2.fetchone()
                        if not row_dest or not row_dest[0]:
                            raise ValueError("Destinatario senza chiave pubblica")
                        pub_dest = PublicKey(base64.b64decode(row_dest[0]))
                    finally:
                        conn2.close()

                    box = Box(eph_priv, pub_dest)
                    shared = box.shared_key()

                else:
                    # 📥 messaggio RICEVUTO da me
                    eph_pub = PublicKey(base64.b64decode(r["ultimo_eph_pub"]))
                    box = Box(priv, eph_pub)
                    shared = box.shared_key()

                cipher = AES.new(shared, AES.MODE_GCM, nonce=nonce)
                testo = cipher.decrypt_and_verify(ct, tag).decode("utf-8")

            except Exception as e:
                print(f"[Errore decifrando ultimo messaggio thread con {r['altro_id']}] {e}")
                testo = "🔒 Messaggio cifrato"

        d["ultimo_testo"] = testo
        threads.append(d)

    return threads

def chat_segna_letti(user_id: int, other_id: int):
    """Segna tutti i messaggi ricevuti dall’altro come letti."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        UPDATE messaggi_chat
        SET letto = 1
        WHERE destinatario_id = ? AND mittente_id = ? AND letto = 0
    """, (user_id, other_id))
    conn.commit()
    conn.close()


def count_chat_non_letti(user_id: int) -> int:
    """Conta tutti i messaggi di chat non letti da un utente."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT COUNT(*)
        FROM messaggi_chat mc
        JOIN utenti u ON u.id = mc.mittente_id
        WHERE mc.destinatario_id = ?
          AND mc.letto = 0
          AND u.sospeso = 0
          AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
          AND u.attivo = 1
    """, (user_id,))
    n = fetchone_value(c.fetchone())
    conn.close()
    return n


# ------------------ OPERATORI ------------------ #
def get_operatori(categoria=None, zona=None, filtri=None):
    conn = get_db_connection()
    query = "SELECT * FROM operatori WHERE 1=1"
    params = []

    if categoria:
        query += " AND categoria = ?"
        params.append(categoria)

    if zona:
        query += " AND LOWER(zona) LIKE ?"
        params.append(f"%{zona.lower()}%")

    if filtri:
        for filtro in filtri:
            query += " AND filtri_categoria LIKE ?"
            params.append(f"%{filtro}%")

    res = conn.execute(query, params).fetchall()
    conn.close()
    return res

def get_operatore_by_id(id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM operatori WHERE id = ?", (id,)).fetchone()
    conn.close()
    return row

def aggiungi_operatore(nome, categoria, zona, servizi, prezzo, bio, filtri_categoria):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO operatori (nome, categoria, zona, servizi, prezzo, bio, filtri_categoria)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (nome, categoria, zona, servizi, prezzo, bio, filtri_categoria))
    conn.commit()
    conn.close()

def modifica_operatore(id, nome, categoria, zona, servizi, prezzo, bio, filtri_categoria=None):
    conn = get_db_connection()
    if filtri_categoria is not None:
        conn.execute('''
            UPDATE operatori
            SET nome = ?, categoria = ?, zona = ?, servizi = ?, prezzo = ?, bio = ?, filtri_categoria = ?
            WHERE id = ?
        ''', (nome, categoria, zona, servizi, prezzo, bio, filtri_categoria, id))
    else:
        conn.execute('''
            UPDATE operatori
            SET nome = ?, categoria = ?, zona = ?, servizi = ?, prezzo = ?, bio = ?
            WHERE id = ?
        ''', (nome, categoria, zona, servizi, prezzo, bio, id))
    conn.commit()
    conn.close()

def elimina_operatore(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM operatori WHERE id = ?", (id,))
    conn.commit()
    conn.close()

def get_tutte_le_zone():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT DISTINCT zona FROM operatori WHERE zona IS NOT NULL AND zona != ''"
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]

# ------------------ UTENTI ------------------ #
def get_utenti():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM utenti ORDER BY id DESC").fetchall()
    conn.close()
    return rows

def attiva_utente(id):
    conn = get_db_connection()
    conn.execute("UPDATE utenti SET attivo = 1 WHERE id = ?", (id,))
    conn.commit()
    conn.close()

def elimina_utente(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM utenti WHERE id = ?", (id,))
    conn.commit()
    conn.close()

# ------------------ NOTIFICHE ------------------ #
def count_notifiche_non_lette(utente_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT COUNT(*) AS tot FROM notifiche WHERE id_utente = ? AND letta = 0",
        (utente_id,)
    ).fetchone()
    conn.close()
    return row['tot'] if row else 0

def crea_notifica(utente_id, messaggio, link=None, tipo="generica"):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO notifiche (id_utente, messaggio, link, tipo)
        VALUES (?, ?, ?, ?)
    """, (utente_id, messaggio, link, tipo))
    conn.commit()
    conn.close()

    # 🔔 Emissione live del badge aggiornato
    invia_notifica_live(utente_id)

def invia_notifica_live(user_id):
    """Aggiorna in tempo reale il badge notifiche via SocketIO."""
    try:
        from app import socketio
        socketio.emit("update_notifications", {"for_user": user_id}, room=f"user_{user_id}")
    except Exception as e:
        print("⚠️ Errore invio notifica live:", e)

def lista_notifiche(utente_id):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM notifiche WHERE id_utente = ? ORDER BY data DESC",
        (utente_id,)
    ).fetchall()
    conn.close()
    return rows

def marca_notifica_letta(notifica_id):
    conn = get_db_connection()
    conn.execute("UPDATE notifiche SET letta = 1 WHERE id = ?", (notifica_id,))
    conn.commit()
    conn.close()

def elimina_notifica(notifica_id, utente_id):
    """Elimina una singola notifica (solo del proprio utente)."""
    conn = get_db_connection()
    conn.execute("DELETE FROM notifiche WHERE id = ? AND id_utente = ?", (notifica_id, utente_id))
    conn.commit()
    conn.close()

def elimina_tutte_notifiche(utente_id):
    """Elimina tutte le notifiche di un utente."""
    conn = get_db_connection()
    conn.execute("DELETE FROM notifiche WHERE id_utente = ?", (utente_id,))
    conn.commit()
    conn.close()

def segna_tutte_lette(utente_id):
    """Segna tutte le notifiche come lette."""
    conn = get_db_connection()
    conn.execute("UPDATE notifiche SET letta = 1 WHERE id_utente = ?", (utente_id,))
    conn.commit()
    conn.close()

def crea_tabella_annunci():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS annunci (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            utente_id INTEGER NOT NULL,
            categoria TEXT NOT NULL,
            titolo TEXT NOT NULL,
            descrizione TEXT,
            zona TEXT,
            filtri_categoria TEXT,
            data_pubblicazione TEXT DEFAULT (datetime('now')),
            stato TEXT DEFAULT 'in_attesa', -- valori: in_attesa, approvato, rifiutato
            FOREIGN KEY (utente_id) REFERENCES utenti(id)
        )
    """)
    conn.commit()
    conn.close()

def get_messaggi_contatto():
    conn = get_db_connection()

    c = conn.cursor()
    c.execute("SELECT * FROM messaggi_contatto ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ------------------ ANNUNCI ------------------ #
def get_annunci_utente(utente_id):
    """Restituisce tutti gli annunci di un utente (approvati, in attesa o rifiutati)."""
    conn = get_db_connection()

    c = conn.cursor()
    c.execute(sql(f"""
        SELECT id, titolo, categoria, descrizione, zona, filtri_categoria,
               data_pubblicazione, stato
        FROM annunci
        WHERE utente_id = ?
        ORDER BY {dt_sql("data_pubblicazione")} DESC
    """), (utente_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]
# ------------------ RECENSIONI ------------------ #
from datetime import datetime

def get_recensioni_utente(user_id):
    """Restituisce solo le recensioni approvate per l’utente (destinatario)."""
    conn = get_db_connection()

    cur = conn.cursor()
    cur.execute("""
        SELECT
            r.id,
            r.id_autore,
            r.id_destinatario,
            r.voto,
            r.testo,
            r.data,
            u.username AS autore_username,
            u.nome AS autore_nome,
            u.cognome AS autore_cognome,
            u.foto_profilo
        FROM recensioni r
        JOIN utenti u ON u.id = r.id_autore
        WHERE r.id_destinatario = ? AND r.stato = 'approvato'
        ORDER BY r.data DESC
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_recensioni_scritte(id_autore):
    """Restituisce tutte le recensioni scritte dall'utente loggato (autore), con eventuali risposte approvate."""
    conn = get_db_connection()

    cur = conn.cursor()
    cur.execute("""
        SELECT
            r.*,
            u.username AS username,
            u.nome AS destinatario_nome,
            u.cognome AS destinatario_cognome,
            u.foto_profilo,
            rr.testo AS risposta_testo,
            rr.stato AS risposta_stato,
            ra.username AS risposta_autore_username,
            ra.nome AS risposta_autore_nome,
            ra.cognome AS risposta_autore_cognome
        FROM recensioni r
        JOIN utenti u ON u.id = r.id_destinatario
        LEFT JOIN risposte_recensioni rr ON rr.id_recensione = r.id AND rr.stato = 'approvato'
        LEFT JOIN utenti ra ON rr.id_autore = ra.id
        WHERE r.id_autore = ?
        ORDER BY r.data DESC
    """, (id_autore,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_recensione_autore_vs_destinatario(id_autore, id_destinatario):
    """Restituisce la recensione che un autore ha lasciato a un destinatario."""
    conn = get_db_connection()

    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM recensioni
        WHERE id_autore = ? AND id_destinatario = ?
    """, (id_autore, id_destinatario))
    row = cur.fetchone()
    conn.close()
    return row


def aggiungi_o_modifica_recensione(id_autore, id_destinatario, voto, testo, stato=None):
    """
    Aggiunge o modifica una recensione.
    - Se `stato` è passato, viene usato (approvato / in_attesa)
    - Se non è passato, usa logica storica:
        • testo vuoto → approvato
        • testo presente → in_attesa
    """

    if not (1 <= int(voto) <= 5):
        raise ValueError("Il voto deve essere compreso tra 1 e 5")

    # Se non viene passato lo stato, decidi qui
    if stato is None:
        stato = "approvato" if testo.strip() == "" else "in_attesa"

    conn = get_db_connection()
    cur = conn.cursor()

    # Verifica se esiste già una recensione
    cur.execute("""
        SELECT id FROM recensioni
        WHERE id_autore = ? AND id_destinatario = ?
    """, (id_autore, id_destinatario))
    esistente = cur.fetchone()

    if esistente:
        # Modifica esistente
        cur.execute("""
            UPDATE recensioni
            SET voto = ?, testo = ?, ultima_modifica = CURRENT_TIMESTAMP, stato = ?
            WHERE id_autore = ? AND id_destinatario = ?
        """, (voto, testo, stato, id_autore, id_destinatario))
    else:
        # Nuova recensione
        cur.execute("""
            INSERT INTO recensioni (id_autore, id_destinatario, voto, testo, stato, data)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (id_autore, id_destinatario, voto, testo, stato))

    conn.commit()
    conn.close()

def calcola_media_recensioni(user_id):
    """Calcola media e numero solo delle recensioni approvate."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT AVG(voto) AS media, COUNT(*) AS n
        FROM recensioni
        WHERE id_destinatario = ? AND stato = 'approvato'
    """, (user_id,))

    row = cur.fetchone()
    conn.close()

    media = row["media"]
    n = row["n"]

    return round(float(media), 1) if media else 0, n

def get_tutte_recensioni():
    conn = get_db_connection()

    c = conn.cursor()

    c.execute("""
        SELECT
            r.id,
            r.id_autore,
            r.id_destinatario,
            r.voto,
            r.testo,
            r.data,
            r.stato,
            a.nome || ' ' || a.cognome AS nome_autore,
            d.nome || ' ' || d.cognome AS nome_destinatario
        FROM recensioni r
        LEFT JOIN utenti a ON r.id_autore = a.id
        LEFT JOIN utenti d ON r.id_destinatario = d.id
        ORDER BY r.data DESC
    """)

    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_tutte_recensioni_con_risposte():
    """Restituisce tutte le recensioni con eventuali risposte (anche in_attesa o rifiutate)."""
    conn = get_db_connection()

    c = conn.cursor()

    c.execute("""
        SELECT
            r.id AS recensione_id,
            r.voto,
            r.testo,
            r.stato,
            r.data AS data_recensione,

            -- 🔹 AUTORE RECENSIONE
            a.id AS autore_id,
            a.nome AS autore_nome,
            a.cognome AS autore_cognome,
            a.email AS autore_email,

            -- 🔹 DESTINATARIO RECENSIONe
            d.id AS dest_id,
            d.nome AS dest_nome,
            d.cognome AS dest_cognome,
            d.email AS dest_email,

            -- 🔹 EVENTUALE RISPOSTA
            rr.id AS risposta_id,
            rr.testo AS risposta_testo,
            rr.stato AS risposta_stato,

            -- 🔹 AUTORE della risposta
            ra.nome AS risposta_autore_nome,
            ra.cognome AS risposta_autore_cognome
        FROM recensioni r
        JOIN utenti a ON r.id_autore = a.id
        JOIN utenti d ON r.id_destinatario = d.id
        LEFT JOIN risposte_recensioni rr ON rr.id_recensione = r.id
        LEFT JOIN utenti ra ON rr.id_autore = ra.id
        ORDER BY r.data DESC
    """)

    result = [dict(r) for r in c.fetchall()]
    conn.close()
    return result

def elimina_recensione(id_recensione, id_autore=None, is_admin=False):
    """Elimina una recensione (solo autore o admin)."""
    conn = get_db_connection()
    cur = conn.cursor()
    if is_admin:
        cur.execute("DELETE FROM recensioni WHERE id = ?", (id_recensione,))
    else:
        cur.execute("DELETE FROM recensioni WHERE id = ? AND id_autore = ?", (id_recensione, id_autore))
    conn.commit()
    conn.close()

# ------------------ RISPOSTE ------------------ #
def get_risposta_by_recensione(id_recensione, solo_approvate=True):
    """Restituisce la risposta (solo se approvata se richiesto)."""
    conn = get_db_connection()

    sql = """
        SELECT
            rr.id,
            rr.id_recensione,
            rr.id_autore,
            rr.testo,
            rr.data,
            rr.stato,
            rr.ultima_modifica,
            u.username AS autore_username,
            u.nome AS autore_nome,
            u.cognome AS autore_cognome,
            u.foto_profilo
        FROM risposte_recensioni rr
        JOIN utenti u ON rr.id_autore = u.id
        WHERE rr.id_recensione = ?
    """
    if solo_approvate:
        sql += " AND rr.stato = 'approvato'"
    cur = conn.cursor()
    cur.execute(sql, (id_recensione,))
    row = cur.fetchone()
    conn.close()
    return row


def aggiungi_o_modifica_risposta(id_recensione=None, id_autore=None, testo=None, id_risposta=None):
    """
    Crea o modifica una risposta, impostandola sempre come 'in_attesa'.
    Può essere chiamata in due modi:
      - nuova risposta → passa id_recensione + id_autore + testo
      - modifica risposta → passa id_risposta + testo
    """
    if not testo or testo.strip() == "":
        raise ValueError("Il testo della risposta non può essere vuoto")

    conn = get_db_connection()
    cur = conn.cursor()

    if id_risposta:  # 🟢 MODIFICA risposta esistente
        cur.execute("""
            UPDATE risposte_recensioni
            SET testo = ?, ultima_modifica = CURRENT_TIMESTAMP, stato = 'in_attesa'
            WHERE id = ?
        """, (testo.strip(), id_risposta))
    else:  # 🟢 NUOVA risposta
        # controlla se esiste già una risposta per quella recensione e autore
        esistente = cur.execute("""
            SELECT id FROM risposte_recensioni
            WHERE id_recensione = ? AND id_autore = ?
        """, (id_recensione, id_autore)).fetchone()

        if esistente:
            cur.execute("""
                UPDATE risposte_recensioni
                SET testo = ?, ultima_modifica = CURRENT_TIMESTAMP, stato = 'in_attesa'
                WHERE id_recensione = ? AND id_autore = ?
            """, (testo.strip(), id_recensione, id_autore))
        else:
            cur.execute("""
                INSERT INTO risposte_recensioni (id_recensione, id_autore, testo, stato, data)
                VALUES (?, ?, ?, 'in_attesa', datetime('now'))
            """, (id_recensione, id_autore, testo.strip()))

    conn.commit()
    conn.close()

    # 🧹 Aggiorna immediatamente badge admin
    try:
        from app import invalidate_admin_counters
        invalidate_admin_counters()
    except Exception as e:
        print(f"⚠️ Errore aggiornando counters admin: {e}")

def get_tutte_risposte():
    """Restituisce tutte le risposte (per admin)."""
    conn = get_db_connection()

    cur = conn.cursor()
    cur.execute("""
        SELECT rr.*,
               u.nome AS autore_nome,
               u.cognome AS autore_cognome,
               r.testo AS testo_recensione,
               r.id_destinatario
        FROM risposte_recensioni rr
        JOIN utenti u ON rr.id_autore = u.id
        JOIN recensioni r ON rr.id_recensione = r.id
        ORDER BY rr.data DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return rows

def elimina_risposta(id_risposta, id_autore=None, is_admin=False):
    """Elimina una risposta (consentito all'autore o all'admin)."""
    conn = get_db_connection()
    cur = conn.cursor()
    if is_admin:
        cur.execute("DELETE FROM risposte_recensioni WHERE id = ?", (id_risposta,))
    else:
        cur.execute("DELETE FROM risposte_recensioni WHERE id = ? AND id_autore = ?", (id_risposta, id_autore))
    conn.commit()
    conn.close()


# ------------------ APPROVAZIONE GENERICA ------------------ #
from threading import Lock
db_lock = Lock()  # blocco globale per sicurezza SQLite

def approva_elemento(tabella, elemento_id):
    """Approva recensione o risposta SENZA creare notifiche di approvazione."""
    if tabella not in ("recensioni", "risposte_recensioni"):
        raise ValueError("Tabella non valida per approvazione")

    with db_lock:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(f"UPDATE {tabella} SET stato = 'approvato' WHERE id = ?", (elemento_id,))
        conn.commit()
        conn.close()


def rifiuta_elemento(tabella, elemento_id):
    """Rifiuta recensione o risposta e invia notifica all'autore."""
    if tabella not in ("recensioni", "risposte_recensioni"):
        raise ValueError("Tabella non valida per rifiuto")

    with db_lock:
        conn = get_db_connection()
        c = conn.cursor()

        # Aggiorna stato
        c.execute(f"UPDATE {tabella} SET stato = 'rifiutato' WHERE id = ?", (elemento_id,))

        if tabella == "recensioni":
            c.execute("""
                SELECT r.id_autore, ud.username AS dest_username
                FROM recensioni r
                JOIN utenti ud ON ud.id = r.id_destinatario
                WHERE r.id = ?
            """, (elemento_id,))
            row = c.fetchone()

        elif tabella == "risposte_recensioni":
            c.execute("""
                SELECT rr.id_autore, ua.username AS username_autore_recensione
                FROM risposte_recensioni rr
                JOIN recensioni r ON rr.id_recensione = r.id
                JOIN utenti ua ON ua.id = r.id_autore
                WHERE rr.id = ?
            """, (elemento_id,))
            row = c.fetchone()

        conn.commit()
        conn.close()

    # ------------------ FUNZIONI COMUNI DI APPROVAZIONE ------------------ #
