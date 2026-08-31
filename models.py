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
# CHAT – STATO BLOCCO TRA UTENTI
# ------------------------------------------------------
def _chat_stato_blocco_cursor(c, user_id: int, other_id: int):
    """
    Legge lo stato del blocco utilizzando un cursore già aperto.
    Il blocco è direzionale, ma la conversazione è considerata
    bloccata se esiste in almeno uno dei due sensi.
    """
    user_id = int(user_id)
    other_id = int(other_id)

    c.execute(sql("""
        SELECT bloccante_id, bloccato_id
        FROM chat_blocchi
        WHERE (bloccante_id = ? AND bloccato_id = ?)
           OR (bloccante_id = ? AND bloccato_id = ?)
    """), (
        user_id,
        other_id,
        other_id,
        user_id
    ))

    rows = c.fetchall()

    bloccato_da_me = any(
        int(row["bloccante_id"]) == user_id
        and int(row["bloccato_id"]) == other_id
        for row in rows
    )

    sono_stato_bloccato = any(
        int(row["bloccante_id"]) == other_id
        and int(row["bloccato_id"]) == user_id
        for row in rows
    )

    return {
        "bloccata": bloccato_da_me or sono_stato_bloccato,
        "bloccato_da_me": bloccato_da_me,
        "sono_stato_bloccato": sono_stato_bloccato
    }


def chat_stato_blocco(user_id: int, other_id: int):
    """
    Restituisce lo stato del blocco tra due utenti,
    gestendo autonomamente connessione e cursore.
    """
    conn = get_db_connection()
    c = get_cursor(conn)

    try:
        return _chat_stato_blocco_cursor(
            c,
            user_id,
            other_id
        )
    finally:
        try:
            c.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

def chat_blocca(bloccante_id: int, bloccato_id: int):
    """
    Registra il blocco di un utente.
    Il blocco non è consentito se uno dei due utenti è admin.
    """
    bloccante_id = int(bloccante_id)
    bloccato_id = int(bloccato_id)

    if bloccante_id == bloccato_id:
        raise ValueError("Non puoi bloccare te stesso.")

    conn = get_db_connection()
    c = get_cursor(conn)

    try:
        c.execute(sql("""
            SELECT id, ruolo
            FROM utenti
            WHERE id IN (?, ?)
        """), (
            bloccante_id,
            bloccato_id
        ))

        utenti = {
            int(row["id"]): row["ruolo"]
            for row in c.fetchall()
        }

        if (
            bloccante_id not in utenti
            or bloccato_id not in utenti
        ):
            raise ValueError("Utente non trovato.")

        if (
            utenti[bloccante_id] == "admin"
            or utenti[bloccato_id] == "admin"
        ):
            raise PermissionError(
                "Il blocco non è disponibile nelle chat con l’amministratore."
            )

        c.execute(sql("""
            INSERT INTO chat_blocchi (
                bloccante_id,
                bloccato_id
            )
            VALUES (?, ?)
            ON CONFLICT (bloccante_id, bloccato_id)
            DO NOTHING
        """), (
            bloccante_id,
            bloccato_id
        ))

        # Elimina il ciclo e-mail per ciascuno dei due utenti
        # se non rimangono messaggi non letti in chat non bloccate.
        c.execute(sql("""
            DELETE FROM chat_unread_email_cycles
            WHERE user_id IN (?, ?)
              AND NOT EXISTS (
                  SELECT 1
                  FROM messaggi_chat mc
                  WHERE mc.destinatario_id =
                        chat_unread_email_cycles.user_id
                    AND mc.letto = 0
                    AND NOT EXISTS (
                        SELECT 1
                        FROM chat_blocchi cb
                        WHERE (
                            cb.bloccante_id = mc.mittente_id
                            AND cb.bloccato_id = mc.destinatario_id
                        )
                        OR (
                            cb.bloccante_id = mc.destinatario_id
                            AND cb.bloccato_id = mc.mittente_id
                        )
                    )
              )
        """), (
            bloccante_id,
            bloccato_id
        ))

        conn.commit()

        return _chat_stato_blocco_cursor(
            c,
            bloccante_id,
            bloccato_id
        )

    except Exception:
        conn.rollback()
        raise

    finally:
        try:
            c.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass


def chat_sblocca(bloccante_id: int, bloccato_id: int):
    """
    Rimuove esclusivamente il blocco creato dall’utente corrente.
    Un eventuale blocco nella direzione opposta rimane attivo.
    """
    bloccante_id = int(bloccante_id)
    bloccato_id = int(bloccato_id)

    conn = get_db_connection()
    c = get_cursor(conn)

    try:
        c.execute(sql("""
            DELETE FROM chat_blocchi
            WHERE bloccante_id = ?
              AND bloccato_id = ?
        """), (
            bloccante_id,
            bloccato_id
        ))

        conn.commit()

        return _chat_stato_blocco_cursor(
            c,
            bloccante_id,
            bloccato_id
        )

    except Exception:
        conn.rollback()
        raise

    finally:
        try:
            c.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

# ------------------------------------------------------
# CHAT – CIFRATURA E DECIFRATURA
# ------------------------------------------------------
def chat_invia(mittente_id: int, destinatario_id: int, testo: str):
    """Cifra il messaggio con ECDH (X25519) + AES-GCM e lo salva nel DB."""
    from nacl.public import Box

    conn = get_db_connection()
    c = get_cursor(conn)

    # Il controllo è eseguito anche nel modello:
    # non deve essere possibile aggirare il blocco dal client.
    stato_blocco = _chat_stato_blocco_cursor(
        c,
        mittente_id,
        destinatario_id
    )

    if stato_blocco["bloccata"]:
        try:
            c.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

        if stato_blocco["bloccato_da_me"]:
            raise PermissionError(
                "Hai bloccato questo utente. Sbloccalo per inviare messaggi."
            )

        raise PermissionError(
            "Non puoi inviare messaggi in questa conversazione."
        )

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

def chat_modifica(
    mittente_id: int,
    messaggio_id: int,
    nuovo_testo: str
):
    """
    Modifica un messaggio inviato entro 15 minuti.

    Il testo precedente viene sostituito e il nuovo contenuto
    viene cifrato nuovamente con chiave effimera, nonce e tag nuovi.
    """
    from datetime import datetime, timezone, timedelta
    from nacl.public import Box

    try:
        mittente_id = int(mittente_id)
        messaggio_id = int(messaggio_id)
    except (TypeError, ValueError):
        raise ValueError("Identificativo messaggio non valido")

    nuovo_testo = str(nuovo_testo or "").strip()

    if not nuovo_testo:
        raise ValueError("Il messaggio non può essere vuoto")

    conn = get_db_connection()
    c = get_cursor(conn)

    def to_utc(value):
        if value is None:
            return None

        if isinstance(value, datetime):
            dt = value
        else:
            valore = str(value).strip()

            if valore.endswith("Z"):
                valore = valore[:-1] + "+00:00"

            dt = datetime.fromisoformat(
                valore.replace(" ", "T", 1)
            )

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    try:
        blocco_riga = (
            " FOR UPDATE"
            if is_postgres()
            else ""
        )

        query_messaggio = """
            SELECT
                id,
                mittente_id,
                destinatario_id,
                created_at,
                deleted_at,
                CURRENT_TIMESTAMP AS server_now
            FROM messaggi_chat
            WHERE id = ?
        """ + blocco_riga

        c.execute(
            sql(query_messaggio),
            (messaggio_id,)
        )

        messaggio = c.fetchone()

        if not messaggio:
            raise ValueError("Messaggio non trovato")

        if int(messaggio["mittente_id"]) != mittente_id:
            raise PermissionError(
                "Non puoi modificare questo messaggio"
            )

        if messaggio["deleted_at"] is not None:
            raise ValueError(
                "Un messaggio eliminato non può essere modificato"
            )

        created_at = to_utc(
            messaggio["created_at"]
        )
        server_now = to_utc(
            messaggio["server_now"]
        )

        if not created_at or not server_now:
            raise ValueError(
                "Impossibile verificare l'orario del messaggio"
            )

        if server_now - created_at > timedelta(minutes=15):
            raise PermissionError(
                "Il tempo disponibile per modificare il messaggio è scaduto"
            )

        destinatario_id = int(
            messaggio["destinatario_id"]
        )

        stato_blocco = _chat_stato_blocco_cursor(
            c,
            mittente_id,
            destinatario_id
        )

        if stato_blocco["bloccata"]:
            raise PermissionError(
                "Non puoi modificare messaggi in una conversazione bloccata"
            )

        # Recupera le chiavi del mittente dalla sessione.
        x_priv_b64 = session.get(
            "x25519_priv_b64"
        )
        dek_b64 = session.get(
            "dek_b64"
        )

        # Fallback sicuro se le chiavi non sono presenti
        # direttamente nella sessione realtime.
        if not x_priv_b64 or not dek_b64:
            c.execute(sql("""
                SELECT
                    dek_enc,
                    dek_nonce,
                    x25519_priv_enc,
                    x25519_priv_nonce
                FROM utenti
                WHERE id = ?
            """), (mittente_id,))

            sender_row = c.fetchone()

            if not sender_row:
                raise ValueError(
                    "Mittente non trovato"
                )

            dek = _decrypt_with_master_local(
                sender_row["dek_enc"],
                sender_row["dek_nonce"]
            )

            x_nonce = base64.b64decode(
                sender_row["x25519_priv_nonce"]
            )
            x_ct, x_tag = _gcm_unpack_local(
                sender_row["x25519_priv_enc"]
            )

            cipher_x = AES.new(
                dek,
                AES.MODE_GCM,
                nonce=x_nonce
            )

            x_priv_bytes = (
                cipher_x.decrypt_and_verify(
                    x_ct,
                    x_tag
                )
            )

            x_priv_b64 = base64.b64encode(
                x_priv_bytes
            ).decode()

            dek_b64 = base64.b64encode(
                dek
            ).decode()

        # Recupera la chiave pubblica del destinatario.
        c.execute(sql("""
            SELECT x25519_pub
            FROM utenti
            WHERE id = ?
        """), (destinatario_id,))

        destinatario = c.fetchone()

        dest_pub_b64 = (
            destinatario["x25519_pub"]
            if destinatario
            else None
        )

        if not dest_pub_b64:
            raise ValueError(
                "Destinatario senza chiave pubblica registrata"
            )

        pub_dest = PublicKey(
            base64.b64decode(dest_pub_b64)
        )

        # Genera una nuova chiave effimera.
        eph_priv = PrivateKey.generate()
        eph_pub = eph_priv.public_key

        box = Box(
            eph_priv,
            pub_dest
        )
        shared = box.shared_key()

        # Cifra integralmente il nuovo testo.
        cipher = AES.new(
            shared,
            AES.MODE_GCM
        )

        ciphertext, tag = (
            cipher.encrypt_and_digest(
                nuovo_testo.encode("utf-8")
            )
        )

        blob_b64 = base64.b64encode(
            ciphertext + tag
        ).decode()

        nonce_b64 = base64.b64encode(
            cipher.nonce
        ).decode()

        eph_pub_b64 = base64.b64encode(
            bytes(eph_pub)
        ).decode()

        # Protegge la nuova chiave effimera privata
        # con la DEK personale del mittente.
        dek = base64.b64decode(dek_b64)

        cipher_eph = AES.new(
            dek,
            AES.MODE_GCM
        )

        eph_ct, eph_tag = (
            cipher_eph.encrypt_and_digest(
                bytes(eph_priv)
            )
        )

        eph_priv_enc_b64 = base64.b64encode(
            eph_ct + eph_tag
        ).decode()

        eph_priv_nonce_b64 = base64.b64encode(
            cipher_eph.nonce
        ).decode()

        # Sostituisce definitivamente il vecchio testo cifrato.
        c.execute(sql("""
            UPDATE messaggi_chat
            SET testo = ?,
                ciphertext = ?,
                nonce = ?,
                eph_pub = ?,
                eph_priv_enc = ?,
                eph_priv_nonce = ?,
                edited_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND mittente_id = ?
              AND deleted_at IS NULL
        """), (
            "🔒",
            blob_b64,
            nonce_b64,
            eph_pub_b64,
            eph_priv_enc_b64,
            eph_priv_nonce_b64,
            messaggio_id,
            mittente_id
        ))

        if c.rowcount != 1:
            raise RuntimeError(
                "Il messaggio non è stato modificato"
            )

        c.execute(sql("""
            SELECT
                edited_at,
                updated_at
            FROM messaggi_chat
            WHERE id = ?
        """), (messaggio_id,))

        risultato = c.fetchone()

        conn.commit()

        edited_at = (
            risultato["edited_at"]
            if risultato
            else None
        )
        updated_at = (
            risultato["updated_at"]
            if risultato
            else None
        )

        return {
            "id": messaggio_id,
            "mittente_id": mittente_id,
            "destinatario_id": destinatario_id,
            "testo": nuovo_testo,
            "edited_at": (
                edited_at.isoformat()
                if hasattr(edited_at, "isoformat")
                else edited_at
            ),
            "updated_at": (
                updated_at.isoformat()
                if hasattr(updated_at, "isoformat")
                else updated_at
            )
        }

    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass

        raise

    finally:
        try:
            c.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

def chat_elimina(
    mittente_id: int,
    messaggio_id: int
):
    """
    Elimina per tutti un messaggio inviato entro 60 ore.

    La riga rimane nel database per conservare posizione,
    mittente, destinatario e data, ma il contenuto cifrato
    e tutto il materiale crittografico vengono cancellati.
    """
    from datetime import datetime, timezone, timedelta

    try:
        mittente_id = int(mittente_id)
        messaggio_id = int(messaggio_id)
    except (TypeError, ValueError):
        raise ValueError(
            "Identificativo messaggio non valido"
        )

    conn = get_db_connection()
    c = get_cursor(conn)

    def to_utc(value):
        if value is None:
            return None

        if isinstance(value, datetime):
            dt = value
        else:
            valore = str(value).strip()

            if valore.endswith("Z"):
                valore = valore[:-1] + "+00:00"

            dt = datetime.fromisoformat(
                valore.replace(" ", "T", 1)
            )

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    def iso_value(value):
        if value is None:
            return None

        if hasattr(value, "isoformat"):
            return value.isoformat()

        return str(value)

    try:
        blocco_riga = (
            " FOR UPDATE"
            if is_postgres()
            else ""
        )

        query_messaggio = """
            SELECT
                id,
                mittente_id,
                destinatario_id,
                created_at,
                deleted_at,
                letto,
                CURRENT_TIMESTAMP AS server_now
            FROM messaggi_chat
            WHERE id = ?
        """ + blocco_riga

        c.execute(
            sql(query_messaggio),
            (messaggio_id,)
        )

        messaggio = c.fetchone()

        if not messaggio:
            raise ValueError(
                "Messaggio non trovato"
            )

        if int(messaggio["mittente_id"]) != mittente_id:
            raise PermissionError(
                "Non puoi eliminare questo messaggio"
            )

        destinatario_id = int(
            messaggio["destinatario_id"]
        )

        # Gestione idempotente:
        # se la richiesta precedente è riuscita ma la risposta
        # non è arrivata al browser, il secondo tentativo non fallisce.
        if messaggio["deleted_at"] is not None:
            return {
                "id": messaggio_id,
                "mittente_id": mittente_id,
                "destinatario_id": destinatario_id,
                "deleted_at": iso_value(
                    messaggio["deleted_at"]
                ),
                "gia_eliminato": True
            }

        created_at = to_utc(
            messaggio["created_at"]
        )
        server_now = to_utc(
            messaggio["server_now"]
        )

        if not created_at or not server_now:
            raise ValueError(
                "Impossibile verificare l'orario del messaggio"
            )

        if server_now - created_at > timedelta(hours=60):
            raise PermissionError(
                "Il tempo disponibile per eliminare il messaggio è scaduto"
            )

        # Mantiene la riga come segnaposto, ma elimina
        # definitivamente testo cifrato e chiavi del messaggio.
        # Il messaggio eliminato non deve più risultare non letto.
        c.execute(sql("""
            UPDATE messaggi_chat
            SET testo = ?,
                ciphertext = NULL,
                nonce = NULL,
                eph_pub = NULL,
                eph_priv_enc = NULL,
                eph_priv_nonce = NULL,
                edited_at = NULL,
                deleted_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP,
                letto = 1
            WHERE id = ?
              AND mittente_id = ?
              AND deleted_at IS NULL
        """), (
            "🗑️",
            messaggio_id,
            mittente_id
        ))

        if c.rowcount != 1:
            raise RuntimeError(
                "Il messaggio non è stato eliminato"
            )

        # Verifica quanti messaggi non letti restano
        # complessivamente al destinatario.
        c.execute(sql("""
            SELECT COUNT(*)
            FROM messaggi_chat mc
            WHERE mc.destinatario_id = ?
              AND mc.letto = 0
              AND NOT EXISTS (
                  SELECT 1
                  FROM chat_blocchi cb
                  WHERE (
                      cb.bloccante_id = mc.mittente_id
                      AND cb.bloccato_id = mc.destinatario_id
                  )
                  OR (
                      cb.bloccante_id = mc.destinatario_id
                      AND cb.bloccato_id = mc.mittente_id
                  )
              )
        """), (destinatario_id,))

        messaggi_non_letti = int(
            fetchone_value(c.fetchone()) or 0
        )

        # Se non rimangono messaggi non letti,
        # chiude anche il ciclo delle email promemoria.
        if messaggi_non_letti == 0:
            c.execute(sql("""
                DELETE FROM chat_unread_email_cycles
                WHERE user_id = ?
            """), (destinatario_id,))

        c.execute(sql("""
            SELECT
                deleted_at,
                updated_at
            FROM messaggi_chat
            WHERE id = ?
        """), (messaggio_id,))

        risultato = c.fetchone()

        conn.commit()

        deleted_at = (
            risultato["deleted_at"]
            if risultato
            else None
        )
        updated_at = (
            risultato["updated_at"]
            if risultato
            else None
        )

        return {
            "id": messaggio_id,
            "mittente_id": mittente_id,
            "destinatario_id": destinatario_id,
            "deleted_at": iso_value(deleted_at),
            "updated_at": iso_value(updated_at),
            "messaggi_non_letti": messaggi_non_letti,
            "gia_eliminato": False
        }

    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass

        raise

    finally:
        try:
            c.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

def chat_conversazione(
    user_id: int,
    other_id: int,
    limit: int = 35,
    after_id: int | None = None,
    before_id: int | None = None,
    changed_after=None,
    changed_before=None
):
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

    # La chiusura riguarda esclusivamente la conversazione
    # tra questo utente e lo specifico admin che l'ha chiusa.
    cutoff = None

    if ruolo != "admin":
        row = c.execute("""
            SELECT closed_at
            FROM chat_chiusure
            WHERE admin_id = ?
              AND user_id = ?
            ORDER BY closed_at DESC
            LIMIT 1
        """, (
            other_id,
            user_id
        )).fetchone()

        cutoff = row["closed_at"] if row else None

    # -----------------------------
    # QUERY MESSAGGI
    # -----------------------------

    # Modifiche o eliminazioni di messaggi già esistenti.
    # Entrambi i limiti temporali provengono dal database,
    # evitando di dipendere dall'orologio del dispositivo.
    if (
        changed_after is not None
        and changed_before is not None
    ):
        query = """
            SELECT id, mittente_id, destinatario_id,
                   testo, ciphertext, nonce, eph_pub,
                   eph_priv_enc, eph_priv_nonce,
                   created_at, edited_at, deleted_at, updated_at,
                   consegnato, letto
            FROM messaggi_chat
            WHERE (
                   (mittente_id = ? AND destinatario_id = ?)
                OR (mittente_id = ? AND destinatario_id = ?)
            )
            AND updated_at >= ?
            AND updated_at <= ?
            AND (
                edited_at IS NOT NULL
                OR deleted_at IS NOT NULL
            )
            AND ( ? IS NULL OR created_at > ? )
            ORDER BY updated_at ASC, id ASC
        """

        params = [
            user_id,
            other_id,
            other_id,
            user_id,
            changed_after,
            changed_before,
            cutoff,
            cutoff
        ]

    # Apertura chat: ultimi N messaggi.
    elif after_id is None and before_id is None:

        query = """
            SELECT id, mittente_id, destinatario_id,
                   testo, ciphertext, nonce, eph_pub,
                   eph_priv_enc, eph_priv_nonce,
                   created_at, edited_at, deleted_at, updated_at,
                   consegnato, letto
            FROM (
                SELECT id, mittente_id, destinatario_id,
                       testo, ciphertext, nonce, eph_pub,
                       eph_priv_enc, eph_priv_nonce,
                       created_at, edited_at, deleted_at, updated_at,
                       consegnato, letto
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
                   created_at, edited_at, deleted_at, updated_at,
                   consegnato, letto
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
                   created_at, edited_at, deleted_at, updated_at,
                   consegnato, letto
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

    # Se carico messaggi vecchi, inverto l'ordine.
    if before_id is not None:
        rows = list(reversed(rows))

    # Converte subito tutte le righe in dizionari.
    rows = [dict(r) for r in rows]

    # Un messaggio eliminato conserva la propria posizione
    # nella conversazione, ma non espone più il contenuto.
    for messaggio in rows:
        if messaggio.get("deleted_at") is not None:
            messaggio["testo"] = "Messaggio eliminato"

    # Se non ho la chiave privata, restituisco comunque
    # correttamente gli eventuali segnaposto eliminati.
    x_priv_b64 = session.get("x25519_priv_b64")

    if not x_priv_b64:
        return rows

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
        # Il materiale cifrato dei messaggi eliminati è stato
        # cancellato: non deve essere effettuato alcun tentativo
        # di decifratura.
        if r.get("deleted_at") is not None:
            messaggi_decifrati.append(r)
            continue

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
                edited_at,
                deleted_at,
                updated_at,
                consegnato,
                letto
            FROM messaggi_chat mc
            WHERE (
                mc.mittente_id = ?
                OR mc.destinatario_id = ?
            )
            {filtro_chat}
            AND (
                ? = 'admin'
                OR NOT EXISTS (
                    SELECT 1
                    FROM chat_chiusure cc
                    WHERE cc.user_id = ?
                      AND cc.admin_id = CASE
                          WHEN mc.mittente_id = ?
                          THEN mc.destinatario_id
                          ELSE mc.mittente_id
                      END
                      AND mc.created_at <= cc.closed_at
                )
            )
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
            lm.edited_at AS ultimo_edited_at,
            lm.deleted_at AS ultimo_deleted_at,
            lm.updated_at AS ultimo_updated_at,
            lm.consegnato AS ultimo_consegnato,
            lm.letto AS ultimo_letto,
            (
                SELECT COUNT(*)
                FROM all_msgs unread_msgs
                WHERE unread_msgs.altro_id = a.altro_id
                  AND unread_msgs.mittente_id = a.altro_id
                  AND unread_msgs.letto = 0
                  AND NOT EXISTS (
                      SELECT 1
                      FROM chat_blocchi cb
                      WHERE (
                          cb.bloccante_id =
                              unread_msgs.mittente_id
                          AND cb.bloccato_id =
                              unread_msgs.destinatario_id
                      )
                      OR (
                          cb.bloccante_id =
                              unread_msgs.destinatario_id
                          AND cb.bloccato_id =
                              unread_msgs.mittente_id
                      )
                  )
            ) AS non_letti
        FROM (SELECT DISTINCT altro_id FROM all_msgs) a
        JOIN utenti u ON u.id = a.altro_id
            AND u.sospeso = 0
            AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
            AND u.attivo = 1
        JOIN last_msg lm ON lm.altro_id = a.altro_id
        ORDER BY last_msg_id DESC;
    """, (
        user_id,
        user_id,
        user_id,
        ruolo,
        user_id,
        user_id
    )).fetchall()

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

        testo = (
            "Messaggio eliminato"
            if r["ultimo_deleted_at"] is not None
            else "🔒 Messaggio cifrato"
        )

        if (
            r["ultimo_deleted_at"] is None
            and priv
            and dek
            and r["ultimo_ciphertext"]
        ):
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
    """
    Segna come letti tutti i messaggi ricevuti dall'altro utente.

    Se, dopo l'aggiornamento, il destinatario non ha più alcun
    messaggio non letto, elimina anche il suo ciclo di promemoria email.
    """
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        UPDATE messaggi_chat
        SET letto = 1
        WHERE destinatario_id = ?
          AND mittente_id = ?
          AND letto = 0
    """, (user_id, other_id))


    # Il ciclo termina soltanto quando il contatore complessivo
    # dei messaggi non letti dell'utente torna a zero.
    c.execute("""
        SELECT COUNT(*)
        FROM messaggi_chat mc
        WHERE mc.destinatario_id = ?
          AND mc.letto = 0
          AND NOT EXISTS (
              SELECT 1
              FROM chat_blocchi cb
              WHERE (
                  cb.bloccante_id = mc.mittente_id
                  AND cb.bloccato_id = mc.destinatario_id
              )
              OR (
                  cb.bloccante_id = mc.destinatario_id
                  AND cb.bloccato_id = mc.mittente_id
              )
          )
    """, (user_id,))

    messaggi_non_letti = fetchone_value(c.fetchone())

    if int(messaggi_non_letti or 0) == 0:
        c.execute("""
            DELETE FROM chat_unread_email_cycles
            WHERE user_id = ?
        """, (user_id,))

    conn.commit()


def count_chat_non_letti(user_id: int) -> int:
    """Conta i messaggi non letti, escludendo le chat bloccate."""
    conn = get_db_connection()
    c = get_cursor(conn)

    try:
        c.execute(sql("""
            SELECT COUNT(*)
            FROM messaggi_chat mc
            JOIN utenti u
              ON u.id = mc.mittente_id
            WHERE mc.destinatario_id = ?
              AND mc.letto = 0
              AND u.sospeso = 0
              AND (
                  u.disattivato_admin IS NULL
                  OR u.disattivato_admin = 0
              )
              AND u.attivo = 1
              AND NOT EXISTS (
                  SELECT 1
                  FROM chat_blocchi cb
                  WHERE (
                      cb.bloccante_id = mc.mittente_id
                      AND cb.bloccato_id = mc.destinatario_id
                  )
                  OR (
                      cb.bloccante_id = mc.destinatario_id
                      AND cb.bloccato_id = mc.mittente_id
                  )
              )
        """), (user_id,))

        n = fetchone_value(c.fetchone())
        return int(n or 0)

    finally:
        try:
            c.close()
        except Exception:
            pass

        try:
            conn.close()
        except Exception:
            pass

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

    L'utente non viene cancellato fisicamente dalla tabella utenti:
    viene anonimizzato e marcato come eliminato, così non rompiamo eventuali
    riferimenti storici o vincoli del database.

    Vengono però rimossi i dati operativi collegati:
    - annunci
    - match collegati agli annunci o all'utente
    - recensioni lasciate/ricevute
    - risposte alle recensioni coinvolte
    - messaggi chat
    - chiusure chat
    - notifiche
    - token reset password
    - push subscription
    - revisioni profilo
    - video call log
    - servizi attivi collegati all'utente o ai suoi annunci
    """

    conn = get_db_connection()
    cur = get_cursor(conn)

    id = int(id)

    email_eliminata = f"deleted_user_{id}@deleted.local"
    username_eliminato = f"UTENTE_ELIMINATO_{id}"

    try:
        # =====================================================
        # 1) Elimina i match collegati agli annunci dell'utente
        #    o direttamente all'utente.
        #    Questo risolve l'errore:
        #    match_utenti_annuncio_id_fkey
        # =====================================================
        cur.execute(sql("""
            DELETE FROM match_utenti
            WHERE annuncio_id IN (
                SELECT id
                FROM annunci
                WHERE utente_id = ?
            )
            OR utente_cerca_id = ?
            OR utente_offre_id = ?
        """), (id, id, id))

        # =====================================================
        # 2) Elimina prima lo storico dei servizi collegato
        #    alle attivazioni dell'utente o dei suoi annunci.
        #    Va fatto prima di cancellare attivazioni_servizi,
        #    altrimenti Postgres blocca per FK:
        #    storico_servizi_attivazione_id_fkey.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM storico_servizi
            WHERE attivazione_id IN (
                SELECT id
                FROM attivazioni_servizi
                WHERE utente_id = ?
                OR annuncio_id IN (
                    SELECT id
                    FROM annunci
                    WHERE utente_id = ?
                )
            )
        """), (id, id))

        # =====================================================
        # 3) Elimina servizi attivi collegati all'utente
        #    o ai suoi annunci.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM attivazioni_servizi
            WHERE utente_id = ?
            OR annuncio_id IN (
                SELECT id
                FROM annunci
                WHERE utente_id = ?
            )
        """), (id, id))
        # =====================================================
        # 3) Scollega eventuali acquisti dagli annunci eliminati.
        #    Non cancelliamo gli acquisti perché possono servire
        #    come storico amministrativo/contabile.
        # =====================================================
        cur.execute(sql("""
            UPDATE acquisti
            SET annuncio_id = NULL
            WHERE annuncio_id IN (
                SELECT id
                FROM annunci
                WHERE utente_id = ?
            )
        """), (id,))

        # =====================================================
        # 4) Elimina risposte a recensioni coinvolte.
        #    Va fatto prima di eliminare le recensioni.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM risposte_recensioni
            WHERE id_autore = ?
            OR id_recensione IN (
                SELECT id
                FROM recensioni
                WHERE id_autore = ?
                   OR id_destinatario = ?
            )
        """), (id, id, id))

        # =====================================================
        # 5) Elimina recensioni lasciate o ricevute dall'utente.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM recensioni
            WHERE id_autore = ?
               OR id_destinatario = ?
        """), (id, id))

        # =====================================================
        # 6) Elimina messaggi chat dell'utente.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM messaggi_chat
            WHERE mittente_id = ?
               OR destinatario_id = ?
        """), (id, id))

        # =====================================================
        # 7) Elimina storico chiusure chat.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM chat_chiusure
            WHERE admin_id = ?
               OR user_id = ?
        """), (id, id))

        # =====================================================
        # 8) Elimina notifiche interne dell'utente.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM notifiche
            WHERE id_utente = ?
        """), (id,))

        # =====================================================
        # 9) Elimina token reset password.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM password_reset_tokens
            WHERE utente_id = ?
        """), (id,))

        # =====================================================
        # 10) Elimina push subscription.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM push_subscriptions
            WHERE utente_id = ?
        """), (id,))

        # =====================================================
        # 11) Elimina revisioni profilo.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM revisioni_profilo
            WHERE utente_id = ?
        """), (id,))

        # =====================================================
        # 12) Elimina log videochiamate collegate all'utente.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM video_call_log
            WHERE utente_1 = ?
               OR utente_2 = ?
        """), (id, id))

        # =====================================================
        # 13) Ora si possono eliminare gli annunci.
        # =====================================================
        cur.execute(sql("""
            DELETE FROM annunci
            WHERE utente_id = ?
        """), (id,))

        # =====================================================
        # 14) Infine anonimizza e disattiva l'utente.
        # =====================================================
        cur.execute(sql("""
            UPDATE utenti
            SET
                nome = ?,
                cognome = ?,
                email = ?,
                username = ?,
                password = '',
                foto_profilo = NULL,
                copertina = NULL,
                foto_galleria = NULL,
                attivo = 0,
                sospeso = 0,
                eliminato = 1,
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

    except Exception:
        conn.rollback()
        raise
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
            a.username AS autore_username,
            a.nome AS autore_nome,
            a.cognome AS autore_cognome,
            a.email AS autore_email,

            -- 🔹 DESTINATARIO RECENSIONE
            d.id AS dest_id,
            d.username AS dest_username,
            d.nome AS dest_nome,
            d.cognome AS dest_cognome,
            d.email AS dest_email,

            -- 🔹 EVENTUALE RISPOSTA
            rr.id AS risposta_id,
            rr.testo AS risposta_testo,
            rr.stato AS risposta_stato,

            -- 🔹 AUTORE della risposta
            ra.username AS risposta_autore_username,
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
