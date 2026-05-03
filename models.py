# models.py

from db import (
    get_db_connection,
    get_cursor,
    sql,
    is_postgres,
    dt_sql,
    insert_and_get_id
)
# -----------------------------
# CHAT – FUNZIONI PRINCIPALI (aggiornate con consegnato/letto/orario)
# -----------------------------
import sqlite3
import base64
import os
from flask import session
from Crypto.Cipher import AES
from nacl.public import PrivateKey, PublicKey
from flask_socketio import SocketIO
from realtime import emit_update_notifications
def fetchone_value(row):
    if row is None:
        return None

    # dict puro
    if isinstance(row, dict):
        return next(iter(row.values()))

    # sqlite3.Row / RowMapping / oggetti simili (supportano keys())
    if hasattr(row, "keys"):
        keys = list(row.keys())
        return row[keys[0]] if keys else None

    # tuple/list classici
    return row[0]

# ------------------------------------------------------
# Helper: ottiene la DEK decifrata (dalla sessione)
# ------------------------------------------------------
def _get_dek():
    dek_b64 = session.get("dek_b64")
    if not dek_b64:
        raise ValueError("Chiave DEK non presente in sessione (utente non autenticato correttamente)")
    return base64.b64decode(dek_b64)

def _gcm_unpack_local(b64: str):
    raw = base64.b64decode(b64)
    return raw[:-16], raw[-16:]


def _decrypt_with_master_local(enc_b64: str, nonce_b64: str) -> bytes:
    master_secret_hex = os.getenv("MASTER_SECRET_KEY")
    if not master_secret_hex:
        raise ValueError("MASTER_SECRET_KEY non disponibile")

    master_secret = bytes.fromhex(master_secret_hex)
    if len(master_secret) != 32:
        raise ValueError("MASTER_SECRET_KEY non valida")

    ct, tag = _gcm_unpack_local(enc_b64)
    nonce = base64.b64decode(nonce_b64)

    cipher = AES.new(master_secret, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

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

    conn = get_db_connection()
    c = get_cursor(conn)

    # --- Recupera materiale crittografico mittente ---
    x_priv_b64 = session.get("x25519_priv_b64")
    dek_b64 = session.get("dek_b64")

    if not x_priv_b64 or not dek_b64:
        c.execute(sql("""
            SELECT dek_enc, dek_nonce, x25519_priv_enc, x25519_priv_nonce
            FROM utenti
            WHERE id = ?
        """), (mittente_id,))
        sender_row = c.fetchone()

        if not sender_row:
            raise ValueError("Mittente non trovato")

        dek = _decrypt_with_master_local(sender_row["dek_enc"], sender_row["dek_nonce"])

        x_nonce = base64.b64decode(sender_row["x25519_priv_nonce"])
        x_ct, x_tag = _gcm_unpack_local(sender_row["x25519_priv_enc"])

        cipher_x = AES.new(dek, AES.MODE_GCM, nonce=x_nonce)
        x_priv_bytes = cipher_x.decrypt_and_verify(x_ct, x_tag)

        x_priv_b64 = base64.b64encode(x_priv_bytes).decode()
        dek_b64 = base64.b64encode(dek).decode()

    x_priv_bytes = base64.b64decode(x_priv_b64)
    priv_mittente = PrivateKey(x_priv_bytes)

    # --- Recupera chiave pubblica del destinatario ---
    c.execute(sql("SELECT x25519_pub FROM utenti WHERE id = ?"), (destinatario_id,))
    row = c.fetchone()

    dest_pub_b64 = (row["x25519_pub"] if row else None)
    if not dest_pub_b64:
        raise ValueError("Destinatario senza chiave pubblica registrata")

    pub_dest = PublicKey(base64.b64decode(dest_pub_b64))

    # --- Genera chiave effimera e calcola chiave condivisa ---
    eph_priv = PrivateKey.generate()
    eph_pub = eph_priv.public_key

    box = Box(eph_priv, pub_dest)
    shared = box.shared_key()

    # --- Cifra testo con AES-GCM ---
    cipher = AES.new(shared, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(testo.encode())

    blob_b64 = base64.b64encode(ciphertext + tag).decode()
    nonce_b64 = base64.b64encode(cipher.nonce).decode()
    eph_pub_b64 = base64.b64encode(bytes(eph_pub)).decode()

    # --- Cifra la chiave effimera privata con la DEK personale ---
    dek = base64.b64decode(dek_b64)
    cipher_eph = AES.new(dek, AES.MODE_GCM)
    eph_ct, eph_tag = cipher_eph.encrypt_and_digest(bytes(eph_priv))
    eph_priv_enc_b64 = base64.b64encode(eph_ct + eph_tag).decode()
    eph_priv_nonce_b64 = base64.b64encode(cipher_eph.nonce).decode()

    # --- Salva nel DB ---
    msg_id = insert_and_get_id(
        c,
        """
        INSERT INTO messaggi_chat (
            mittente_id, destinatario_id, testo,
            ciphertext, nonce, eph_pub,
            eph_priv_enc, eph_priv_nonce,
            consegnato, letto
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
        """,
        (
            mittente_id, destinatario_id, "🔒",
            blob_b64, nonce_b64, eph_pub_b64,
            eph_priv_enc_b64, eph_priv_nonce_b64
        )
    )

    conn.commit()
    return msg_id

def chat_conversazione(user_id: int, other_id: int, limit: int = 35, after_id: int | None = None, before_id: int | None = None):
    """
    Restituisce la conversazione decifrando i messaggi leggibili con la chiave privata X25519.
    LOGICA IDENTICA, solo ottimizzata.
    """

    from nacl.public import PrivateKey, PublicKey, Box
    from Crypto.Cipher import AES
    import base64

    conn = get_db_connection()
    c = get_cursor(conn)

    # 🔍 Recupera ruolo utente
    ruolo_row = c.execute(
        "SELECT ruolo FROM utenti WHERE id = ?",
        (user_id,)
    ).fetchone()

    ruolo = ruolo_row["ruolo"] if ruolo_row else None

    # 🔪 cutoff solo per NON admin
    cutoff = None
    if ruolo != "admin":
        row = c.execute("""
            SELECT closed_at
            FROM chat_chiusure
            WHERE admin_id = 1 AND user_id = ?
            ORDER BY closed_at DESC
            LIMIT 1
        """, (user_id,)).fetchone()
        cutoff = row["closed_at"] if row else None

    # -----------------------------
    # QUERY MESSAGGI
    # -----------------------------

    # apertura chat (ultimi N messaggi)
    if after_id is None and before_id is None:

        query = """
            SELECT id, mittente_id, destinatario_id,
                   testo, ciphertext, nonce, eph_pub,
                   eph_priv_enc, eph_priv_nonce,
                   created_at, consegnato, letto
            FROM (
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
                ORDER BY id DESC
                LIMIT ?
            ) t
            ORDER BY id ASC
        """

        params = [user_id, other_id, other_id, user_id, cutoff, cutoff, limit]

    # nuovi messaggi (polling)
    elif after_id is not None:

        query = """
            SELECT id, mittente_id, destinatario_id,
                   testo, ciphertext, nonce, eph_pub,
                   eph_priv_enc, eph_priv_nonce,
                   created_at, consegnato, letto
            FROM messaggi_chat
            WHERE (
                   (mittente_id = ? AND destinatario_id = ?)
                OR (mittente_id = ? AND destinatario_id = ?)
            )
            AND id > ?
            AND ( ? IS NULL OR created_at > ? )
            ORDER BY id ASC
        """

        params = [user_id, other_id, other_id, user_id, after_id, cutoff, cutoff]

    # messaggi più vecchi (scroll verso l'alto)
    else:

        query = """
            SELECT id, mittente_id, destinatario_id,
                   testo, ciphertext, nonce, eph_pub,
                   eph_priv_enc, eph_priv_nonce,
                   created_at, consegnato, letto
            FROM messaggi_chat
            WHERE (
                   (mittente_id = ? AND destinatario_id = ?)
                OR (mittente_id = ? AND destinatario_id = ?)
            )
            AND id < ?
            AND ( ? IS NULL OR created_at > ? )
            ORDER BY id DESC
            LIMIT ?
        """

        params = [user_id, other_id, other_id, user_id, before_id, cutoff, cutoff, limit]

    rows = c.execute(sql(query), params).fetchall()

    # se carico messaggi vecchi invertiamo ordine
    if before_id is not None:
        rows = list(reversed(rows))

    # 🔑 Se non ho chiave privata → ritorno senza decrypt
    x_priv_b64 = session.get("x25519_priv_b64")
    if not x_priv_b64:
        return [dict(r) for r in rows]

    priv = PrivateKey(base64.b64decode(x_priv_b64))
    dek = base64.b64decode(session["dek_b64"])

    # 🔥 OTTIMIZZAZIONE CRITICA:
    # Recupero UNA SOLA VOLTA la chiave pubblica dell'altro utente
    row_dest = c.execute(
        "SELECT x25519_pub FROM utenti WHERE id = ?",
        (other_id,)
    ).fetchone()

    dest_pub = None
    if row_dest and row_dest["x25519_pub"]:
        dest_pub = PublicKey(base64.b64decode(row_dest["x25519_pub"]))

    messaggi_decifrati = []

    for r in rows:
        r = dict(r)

        try:
            raw = base64.b64decode(r["ciphertext"])
            nonce = base64.b64decode(r["nonce"])
            ct, tag = raw[:-16], raw[-16:]

            # 🔹 Se il messaggio è stato INVIATO da me
            if r["mittente_id"] == user_id:

                if not r.get("eph_priv_enc") or not r.get("eph_priv_nonce"):
                    raise ValueError("Chiave effimera privata mancante")

                eph_ct_raw = base64.b64decode(r["eph_priv_enc"])
                eph_nonce = base64.b64decode(r["eph_priv_nonce"])
                eph_ct, eph_tag = eph_ct_raw[:-16], eph_ct_raw[-16:]

                cipher_eph = AES.new(dek, AES.MODE_GCM, nonce=eph_nonce)
                eph_priv_bytes = cipher_eph.decrypt_and_verify(eph_ct, eph_tag)
                eph_priv = PrivateKey(eph_priv_bytes)

                if not dest_pub:
                    raise ValueError("Destinatario senza chiave pubblica")

                box = Box(eph_priv, dest_pub)
                shared = box.shared_key()

            else:
                # 🔹 Sono il destinatario
                eph_pub = PublicKey(base64.b64decode(r["eph_pub"]))
                box = Box(priv, eph_pub)
                shared = box.shared_key()

            cipher = AES.new(shared, AES.MODE_GCM, nonce=nonce)
            r["testo"] = cipher.decrypt_and_verify(ct, tag).decode()

        except Exception as e:
            print(f"[Errore decifrando messaggio chat {r.get('id')}] {e}")
            r["testo"] = "🔒 Messaggio cifrato"

        messaggi_decifrati.append(r)

    return messaggi_decifrati

def chat_threads(user_id: int):
    """
    Logica IDENTICA alla tua.
    Solo ottimizzata per evitare connessioni DB dentro il loop.
    """

    from nacl.public import PrivateKey, PublicKey, Box
    from Crypto.Cipher import AES
    import base64

    conn = get_db_connection()
    c = get_cursor(conn)

    # 🔍 Ruolo utente
    ruolo_row = c.execute(
        "SELECT ruolo FROM utenti WHERE id = ?",
        (user_id,)
    ).fetchone()
    ruolo = ruolo_row["ruolo"] if ruolo_row else None

    cutoff = None
    if ruolo != "admin":
        row = c.execute("""
            SELECT closed_at
            FROM chat_chiusure
            WHERE admin_id = 1 AND user_id = ?
            ORDER BY closed_at DESC
            LIMIT 1
        """, (user_id,)).fetchone()
        cutoff = row["closed_at"] if row else None

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
            SELECT *
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
            lm.id AS last_msg_id,
            lm.mittente_id AS ultimo_mittente_id,
            lm.destinatario_id AS ultimo_destinatario_id,
            lm.ciphertext AS ultimo_ciphertext,
            lm.nonce AS ultimo_nonce,
            lm.eph_pub AS ultimo_eph_pub,
            lm.eph_priv_enc AS ultimo_eph_priv_enc,
            lm.eph_priv_nonce AS ultimo_eph_priv_nonce,
            lm.created_at AS ultimo_invio,
            lm.consegnato AS ultimo_consegnato,
            lm.letto AS ultimo_letto,
            (
                SELECT COUNT(*)
                FROM all_msgs
                WHERE altro_id = a.altro_id
                  AND mittente_id = a.altro_id
                  AND letto = 0
            ) AS non_letti
        FROM (SELECT DISTINCT altro_id FROM all_msgs) a
        JOIN utenti u ON u.id = a.altro_id
            AND u.sospeso = 0
            AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
            AND u.attivo = 1
        JOIN last_msg lm ON lm.altro_id = a.altro_id
        ORDER BY last_msg_id DESC;
    """, (user_id, user_id, user_id, cutoff, cutoff)).fetchall()

    # 🔑 Recupero chiavi sessione
    x_priv_b64 = session.get("x25519_priv_b64")
    dek_b64 = session.get("dek_b64")

    priv = None
    dek = None

    if x_priv_b64 and dek_b64:
        priv = PrivateKey(base64.b64decode(x_priv_b64))
        dek = base64.b64decode(dek_b64)

    # 🔥 OTTIMIZZAZIONE CHIAVE PUBBLICA
    # Recuperiamo tutte le chiavi pubbliche in UNA SOLA QUERY
    altro_ids = [r["altro_id"] for r in rows]

    pub_keys = {}
    if altro_ids:
        placeholders = ",".join(["?"] * len(altro_ids))
        rows_pub = c.execute(
            f"SELECT id, x25519_pub FROM utenti WHERE id IN ({placeholders})",
            altro_ids
        ).fetchall()

        for row in rows_pub:
            if row["x25519_pub"]:
                pub_keys[row["id"]] = PublicKey(
                    base64.b64decode(row["x25519_pub"])
                )

    threads = []

    for r in rows:
        d = dict(r)

        d["altro_username"] = r["username_altro"]
        d["nome_chat"] = "@" + d["altro_username"]

        testo = "🔒 Messaggio cifrato"

        if priv and dek and r["ultimo_ciphertext"]:
            try:
                raw = base64.b64decode(r["ultimo_ciphertext"])
                nonce = base64.b64decode(r["ultimo_nonce"])
                ct, tag = raw[:-16], raw[-16:]

                if r["ultimo_mittente_id"] == user_id:
                    # 📨 messaggio inviato da me
                    eph_ct_raw = base64.b64decode(r["ultimo_eph_priv_enc"])
                    eph_nonce = base64.b64decode(r["ultimo_eph_priv_nonce"])
                    eph_ct, eph_tag = eph_ct_raw[:-16], eph_ct_raw[-16:]

                    cipher_eph = AES.new(dek, AES.MODE_GCM, nonce=eph_nonce)
                    eph_priv_bytes = cipher_eph.decrypt_and_verify(eph_ct, eph_tag)
                    eph_priv = PrivateKey(eph_priv_bytes)

                    pub_dest = pub_keys.get(r["altro_id"])
                    if not pub_dest:
                        raise ValueError("Destinatario senza chiave pubblica")

                    box = Box(eph_priv, pub_dest)
                    shared = box.shared_key()

                else:
                    # 📥 ricevuto da me
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

    cur = get_cursor(conn)
    res = cur.execute(sql(query), params).fetchall()

    return res

def get_operatore_by_id(id):
    conn = get_db_connection()
    cur = get_cursor(conn)
    row = cur.execute(sql("SELECT * FROM operatori WHERE id = ?"), (id,)).fetchone()

    return row

def aggiungi_operatore(nome, categoria, zona, servizi, prezzo, bio, filtri_categoria):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO operatori (nome, categoria, zona, servizi, prezzo, bio, filtri_categoria)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (nome, categoria, zona, servizi, prezzo, bio, filtri_categoria))
    conn.commit()


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


def elimina_operatore(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM operatori WHERE id = ?", (id,))
    conn.commit()


def get_tutte_le_zone():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT DISTINCT zona FROM operatori WHERE zona IS NOT NULL AND zona != ''"
    ).fetchall()

    return [r[0] for r in rows]

# ------------------ UTENTI ------------------ #
def get_utenti():
    conn = get_db_connection()
    cur = get_cursor(conn)
    rows = cur.execute(sql("SELECT * FROM utenti ORDER BY id DESC")).fetchall()

    return rows

def attiva_utente(id):
    conn = get_db_connection()
    conn.execute("UPDATE utenti SET attivo = 1 WHERE id = ?", (id,))
    conn.commit()


def elimina_utente(id):
    """
    Eliminazione sicura lato admin.

    Non cancelliamo fisicamente la riga da utenti perché l'utente può essere
    collegato ad annunci, recensioni, messaggi, notifiche, acquisti, servizi, ecc.

    Quando l'admin elimina un utente:
    - gli annunci dell'utente vengono rimossi;
    - l'account viene disattivato;
    - email e username vengono liberati;
    - il profilo viene reso invisibile;
    - i dati principali vengono anonimizzati.
    """

    conn = get_db_connection()
    cur = get_cursor(conn)

    id = int(id)

    email_eliminata = f"deleted_user_{id}@deleted.local"
    username_eliminato = f"UTENTE_ELIMINATO_{id}"

    # 1) Prima eliminiamo gli annunci dell'utente.
    # Questo fa sparire i suoi annunci dal sito.
    cur.execute(sql("""
        DELETE FROM annunci
        WHERE utente_id = ?
    """), (id,))

    # 2) Poi anonimimizziamo/disattiviamo l'utente senza cancellarlo fisicamente.
    cur.execute(sql("""
        UPDATE utenti
        SET
            nome = ?,
            cognome = ?,
            email = ?,
            username = ?,
            password = '',
            attivo = 0,
            token_verifica = NULL,
            visibile_pubblicamente = 0
        WHERE id = ?
    """), (
        "Utente",
        "eliminato",
        email_eliminata,
        username_eliminato,
        id
    ))

    conn.commit()
    
# ------------------ NOTIFICHE ------------------ #
def count_notifiche_non_lette(utente_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT COUNT(*) AS tot FROM notifiche WHERE id_utente = ? AND letta = 0",
        (utente_id,)
    ).fetchone()

    return row['tot'] if row else 0

def crea_notifica(utente_id, messaggio, link=None, tipo="generica"):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO notifiche (id_utente, messaggio, link, tipo)
        VALUES (?, ?, ?, ?)
    """, (utente_id, messaggio, link, tipo))
    conn.commit()


    # 🔔 Emissione live del badge aggiornato
    invia_notifica_live(utente_id)

from realtime import emit_update_notifications

def invia_notifica_live(user_id):
    emit_update_notifications(user_id)

def lista_notifiche(utente_id):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM notifiche WHERE id_utente = ? ORDER BY data DESC",
        (utente_id,)
    ).fetchall()

    return rows

def marca_notifica_letta(notifica_id):
    conn = get_db_connection()
    conn.execute("UPDATE notifiche SET letta = 1 WHERE id = ?", (notifica_id,))
    conn.commit()


def elimina_notifica(notifica_id, utente_id):
    """Elimina una singola notifica (solo del proprio utente)."""
    conn = get_db_connection()
    conn.execute("DELETE FROM notifiche WHERE id = ? AND id_utente = ?", (notifica_id, utente_id))
    conn.commit()


def elimina_tutte_notifiche(utente_id):
    """Elimina tutte le notifiche di un utente."""
    conn = get_db_connection()
    conn.execute("DELETE FROM notifiche WHERE id_utente = ?", (utente_id,))
    conn.commit()


def segna_tutte_lette(utente_id):
    """Segna tutte le notifiche come lette."""
    conn = get_db_connection()
    conn.execute("UPDATE notifiche SET letta = 1 WHERE id_utente = ?", (utente_id,))
    conn.commit()


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


def get_messaggi_contatto():
    conn = get_db_connection()

    c = conn.cursor()
    c.execute("SELECT * FROM messaggi_contatto ORDER BY id DESC")
    rows = c.fetchall()

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
                VALUES (?, ?, ?, 'in_attesa', CURRENT_TIMESTAMP)
            """, (id_recensione, id_autore, testo.strip()))

    conn.commit()


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


    # ------------------ FUNZIONI COMUNI DI APPROVAZIONE ------------------ #
