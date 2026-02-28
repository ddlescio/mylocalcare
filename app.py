import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
import os
import sqlite3
import json
import uuid
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv  # ✅ serve per leggere il file .env
# 🔐 Crittografia
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import threading
from models import calcola_media_recensioni, get_recensioni_utente
from models import (

    get_operatori, get_operatore_by_id,
    aggiungi_operatore, modifica_operatore, elimina_operatore, get_tutte_le_zone,
    get_utenti, attiva_utente, elimina_utente,
    chat_invia, chat_conversazione, chat_threads, chat_segna_letti, count_chat_non_letti,
    get_recensioni_utente, aggiungi_o_modifica_recensione, get_recensione_autore_vs_destinatario,
    calcola_media_recensioni, get_risposta_by_recensione, aggiungi_o_modifica_risposta, elimina_risposta,
    get_annunci_utente
)
from models import crea_notifica
from flask_login import login_required
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta, timezone
from services import attiva_servizio, revoca_attivazione, servizio_attivo_per_annuncio, servizio_attivo_per_utente
import secrets
import stripe
import psycopg2
import psycopg2.extras
import re
from models import fetchone_value

import os
from flask import g
from db import (insert_and_get_id)
from realtime import emit_update_notifications

# ==========================================================
# DB POOL (Postgres) + Connessione riutilizzabile per-request
# ==========================================================

_pg_pool = None

def init_pg_pool():
    global _pg_pool

    if _pg_pool is not None:
        return

    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        return

    from psycopg2.pool import ThreadedConnectionPool

    _pg_pool = ThreadedConnectionPool(
        minconn=1,
        maxconn=12,
        dsn=dsn,
        sslmode="require",
        cursor_factory=psycopg2.extras.RealDictCursor
    )

def get_cursor(conn):
    import sqlite3
    import psycopg2.extras

    # PostgreSQL (Render)
    if isinstance(conn, psycopg2.extensions.connection):
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # SQLite (locale)
    elif isinstance(conn, sqlite3.Connection):
        conn.row_factory = sqlite3.Row
        return conn.cursor()

    # fallback
    return conn.cursor()

def get_reset_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

# -- Helper per AES-GCM: salviamo ciphertext||tag in un solo campo base64 --
def gcm_pack(ciphertext: bytes, tag: bytes) -> str:
    return base64.b64encode(ciphertext + tag).decode()

def gcm_unpack(b64: str):
    raw = base64.b64decode(b64)
    if len(raw) < 16:
        raise ValueError("GCM blob troppo corto")
    return raw[:-16], raw[-16:]  # (ciphertext, tag)
# 🔐 Per cifratura end-to-end con X25519 (ECDH)
from nacl.public import PrivateKey, PublicKey

import base64
from Crypto.Cipher import AES



def encrypt_with_master(plaintext: bytes) -> tuple[str, str]:
    """
    Cifra bytes con MASTER_SECRET usando AES-GCM.
    Ritorna (ct+tag in base64 'impacchettato' con gcm_pack, nonce_base64).
    """
    cipher = AES.new(MASTER_SECRET, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    dek_enc_b64 = gcm_pack(ct, tag)
    nonce_b64 = base64.b64encode(cipher.nonce).decode()
    return dek_enc_b64, nonce_b64


def decrypt_with_master(enc_b64: str, nonce_b64: str) -> bytes:
    """
    Decifra quello che è stato cifrato con encrypt_with_master.
    """
    ct, tag = gcm_unpack(enc_b64)
    nonce = base64.b64decode(nonce_b64)
    cipher = AES.new(MASTER_SECRET, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def is_admin(user_id):
    conn = get_db_connection()

    c = get_cursor(conn)
    c.execute(
        sql("SELECT ruolo FROM utenti WHERE id=?"),
        (user_id,)
    )
    row = c.fetchone()

    return row and row["ruolo"] == "admin"

import requests

DAILY_BASE_URL = "https://api.daily.co/v1"


def crea_room_daily(nome_room: str):
    """
    Crea una room Daily tramite API.
    """
    url = f"{DAILY_BASE_URL}/rooms"

    headers = {
        "Authorization": f"Bearer {DAILY_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "name": nome_room,
        "properties": {
            "enable_chat": True,
            "start_video_off": False,
            "start_audio_off": False,
            "exp": int(datetime.now().timestamp()) + 3600  # scade tra 1h
        }
    }

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code != 200:
        raise RuntimeError(f"Errore creazione room Daily: {response.text}")

    return response.json()

# ==========================================================
# 🔐 SINCRONIZZAZIONE / GENERAZIONE CHIAVI X25519
# ==========================================================
def ensure_x25519_keys(user_id):
    """Verifica o genera le chiavi X25519 per l'utente (rigenera se mancano o sono incoerenti)"""
    conn = get_db_connection()

    c = get_cursor(conn)
    c.execute(sql("SELECT x25519_pub, x25519_priv_enc, x25519_priv_nonce FROM utenti WHERE id = ?"), (user_id,))
    row = c.fetchone()

    from Crypto.Cipher import AES
    import base64

    if not row or not row["x25519_pub"] or not row["x25519_priv_enc"] or not row["x25519_priv_nonce"]:
        print(f"Rigenerazione chiavi X25519 per utente {user_id}...")
        from nacl.public import PrivateKey

        # Genera nuova coppia
        priv = PrivateKey.generate()
        pub = priv.public_key

        # Decifra DEK dalla sessione
        dek = base64.b64decode(session.get("dek_b64"))
        cipher = AES.new(dek, AES.MODE_GCM)
        priv_enc, tag = cipher.encrypt_and_digest(bytes(priv))
        nonce = cipher.nonce

        # Salva nel DB
        c.execute(sql("""
            UPDATE utenti
            SET x25519_pub = ?, x25519_priv_enc = ?, x25519_priv_nonce = ?
            WHERE id = ?
        """), (
            base64.b64encode(bytes(pub)).decode(),
            base64.b64encode(priv_enc + tag).decode(),
            base64.b64encode(nonce).decode(),
            user_id
        ))
        conn.commit()

        # Aggiorna sessione
        session["x25519_priv_b64"] = base64.b64encode(bytes(priv)).decode()
        session["x25519_pub_b64"] = base64.b64encode(bytes(pub)).decode()

    else:
        # Decifra chiave privata esistente e ricarica in sessione
        dek = base64.b64decode(session.get("dek_b64"))
        priv_enc_raw = base64.b64decode(row["x25519_priv_enc"])
        nonce = base64.b64decode(row["x25519_priv_nonce"])
        ct, tag = priv_enc_raw[:-16], priv_enc_raw[-16:]
        cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce)
        priv_bytes = cipher.decrypt_and_verify(ct, tag)

        session["x25519_priv_b64"] = base64.b64encode(priv_bytes).decode()
        session["x25519_pub_b64"] = row["x25519_pub"]




# Slug -> chiave nel JSON + label umana
CATEGORY_MAP = {
    "operatori-benessere": ("operatori benessere", "Operatori Benessere"),
    "operatori benessere": ("operatori benessere", "Operatori Benessere"),
    "babysitter": ("babysitter", "Babysitter"),
    "petsitter": ("petsitter", "Pet-Sitter"),
    "caregiver": ("caregiver", "Caregiver"),
    "ripetizioni": ("ripetizioni", "Ripetizioni"),
    "aiuto-in-casa": ("aiuto-in-casa", "Aiuto in Casa"),
    "escursioni-sport": ("escursioni-sport", "Escursioni & Sport"),
    "biglietti-spettacoli": ("biglietti-spettacoli", "Biglietti Spettacoli"),
    "libri-scuola": ("libri-scuola", "Libri Scuola"),
    "caffe-parole": ("caffe-parole", "Caffè & Parole"),
}
# =========================================
# MATCH: categorie (ordine = offro_1..offro_10 / cerco_1..cerco_10)
# =========================================
def to_slug(val: str) -> str:
    """minuscolo, spazi -> '-', rimuove underscore, normalizza '&' in '-' """
    if not val:
        return ""
    v = val.strip().lower()
    v = v.replace("_", " ")
    v = v.replace("&", " ")  # niente ampersand negli slug
    v = "-".join(v.split())  # comprime multipli spazi in trattini
    return v




CATEGORIE_PREFERENZE = [
    "Operatori benessere",             # 1
    "Aiuto in casa",                   # 2
    "Ripetizioni",                     # 3
    "Babysitter",                      # 4
    "Pet-sitter",                      # 5
    "Caregiver",                       # 6
    "escursioni-sport",                # 7
    "Biglietti spettacoli",            # 8
    "Libri scuola",                    # 9
    "Caffe & parole",                  # 10
]

# slug -> indice 1..10
CATEGORIA_TO_INDEX = {to_slug(x): i+1 for i, x in enumerate(CATEGORIE_PREFERENZE)}


def norm_place(s: str) -> str:
    """Normalizza città/zona per confronto robusto."""
    if not s:
        return ""
    return " ".join(s.strip().lower().replace("-", " ").split())


def place_match(annuncio_zona: str, utente_citta: str) -> bool:
    """
    Match zona/città:
    True se uguali o uno contiene l'altro (case-insensitive, ripulito).
    """
    a = norm_place(annuncio_zona)
    u = norm_place(utente_citta)
    if not a or not u:
        return False
    return (a == u) or (a in u) or (u in a)


from datetime import datetime
import zoneinfo

# ==========================================================
# 1️⃣ CONFIGURAZIONE DI BASE E APP
# ==========================================================


from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR / ".env.secrets")

MASTER_SECRET_HEX = os.getenv("MASTER_SECRET_KEY")
if not MASTER_SECRET_HEX:
    raise RuntimeError("MASTER_SECRET_KEY non trovata in .env / .env.secrets")

MASTER_SECRET = bytes.fromhex(MASTER_SECRET_HEX)
if len(MASTER_SECRET) != 32:
    raise RuntimeError("MASTER_SECRET_KEY deve essere lunga 32 byte (64 caratteri hex)")

DAILY_API_KEY = os.getenv("DAILY_API_KEY")
if not DAILY_API_KEY:
    raise RuntimeError("DAILY_API_KEY non trovata in .env.secrets")

app = Flask(__name__)
import json
app.jinja_env.filters['from_json'] = lambda s: json.loads(s or "[]")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,  # SOLO se sei su HTTPS
)

@app.before_request
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

def verify_csrf():
    token = None

    # JSON (fetch/AJAX)
    if request.is_json:
        token = request.headers.get("X-CSRF-Token")

    # Form classico
    else:
        token = request.form.get("csrf_token")

    if not token or token != session.get("csrf_token"):
        abort(403)


import os

socketio = SocketIO(
    app,
    cors_allowed_origins=[
        "https://mylocalcare.it",
        "https://www.mylocalcare.it",
        "http://127.0.0.1:5050",
        "http://localhost:5050"
    ],
    async_mode="eventlet"
)

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")

# ==========================================================
# SQL HELPER (placeholder compatibili SQLite / Postgres)
# ==========================================================

def sql(query):
    """
    Converte automaticamente i placeholder:
    SQLite  -> ?
    Postgres -> %s
    """
    if app.config.get("IS_POSTGRES"):
        return query.replace("?", "%s")
    return query

# ==========================================================
# 🕒 FUNZIONI TEMPO COMPATIBILI SQLite + PostgreSQL
# ==========================================================

def now_sql():
    """
    Timestamp corrente compatibile con entrambi i DB.
    """
    if app.config.get("IS_POSTGRES"):
        return "CURRENT_TIMESTAMP"
    else:
        return "datetime('now')"

def month_sql(field=None):
    """
    Restituisce YYYY-MM compatibile SQLite/Postgres.
    """
    if app.config.get("IS_POSTGRES"):
        if field:
            return f"TO_CHAR({field}, 'YYYY-MM')"
        return "TO_CHAR(NOW(), 'YYYY-MM')"
    else:
        if field:
            return f"strftime('%Y-%m', {field})"
        return "strftime('%Y-%m','now')"

def epoch_now_sql():
    """
    Timestamp unix (secondi) compatibile con entrambi i DB.
    """
    if app.config.get("IS_POSTGRES"):
        return "EXTRACT(EPOCH FROM NOW())::INT"
    else:
        return "strftime('%s','now')"


def dt_sql(field):
    """
    Normalizza conversione datetime nelle query ORDER BY.
    """
    if app.config.get("IS_POSTGRES"):
        return field
    else:
        return f"datetime({field})"

def order_datetime(field):
    return field if app.config.get("IS_POSTGRES") else f"datetime({field})"

def get_last_id(cur):
    """
    Compatibile SQLite + PostgreSQL.
    """
    if app.config.get("IS_POSTGRES"):
        return cur.fetchone()[0]
    else:
        return cur.lastrowid



from datetime import datetime
from zoneinfo import ZoneInfo

@app.teardown_request
def _release_pg_conn(exc):
    conn = getattr(g, "db_conn", None)
    if not conn:
        return

    try:
        # ⚠️ IMPORTANTE:
        # non usare putconn manuale
        # il wrapper gestisce già il rilascio al pool
        conn.close()
    except Exception:
        pass

    g.db_conn = None

@app.template_filter("dt_roma")
def dt_roma(value):
    if not value:
        return ""
    dt = datetime.fromisoformat(value)
    return dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(
        ZoneInfo("Europe/Rome")
    ).strftime("%Y-%m-%d %H:%M:%S")

@app.template_filter("fromjson")
def fromjson_filter(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}

from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

def now_utc():
    return datetime.now(timezone.utc)

def parse_iso(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except Exception:
        return None


@app.template_filter('to_datetime')
def to_datetime_filter(value):
    if not value:
        return None
    try:
        v = str(value).replace(" ", "T")
        dt = datetime.fromisoformat(v)

        # se naive → assumo UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as e:
        print("❌ Errore filtro to_datetime:", e)
        return None


@app.template_filter('fmt_it')
def fmt_it(value):
    try:
        dt = to_datetime_filter(value)
        if not dt:
            return value

        dt_it = dt.astimezone(ZoneInfo("Europe/Rome"))
        return dt_it.strftime("%d-%m-%Y %H:%M")
    except Exception as e:
        print("❌ Errore filtro fmt_it:", e)
        return value


@app.template_filter('fmt_it_smart')
def fmt_it_smart(value):
    try:
        dt = to_datetime_filter(value)
        if not dt:
            return value

        roma = ZoneInfo("Europe/Rome")
        dt_it = dt.astimezone(roma)
        now = datetime.now(roma)

        date_it = dt_it.date()
        today = now.date()
        yesterday = (now - timedelta(days=1)).date()

        if date_it == today:
            return f"oggi {dt_it.strftime('%H:%M')}"

        if date_it == yesterday:
            return f"ieri {dt_it.strftime('%H:%M')}"

        if dt_it.isocalendar()[1] == now.isocalendar()[1] and dt_it.year == now.year:
            giorni = ["lunedì","martedì","mercoledì","giovedì","venerdì","sabato","domenica"]
            return f"{giorni[dt_it.weekday()]} {dt_it.strftime('%H:%M')}"

        return dt_it.strftime("%d-%m-%Y %H:%M")

    except Exception as e:
        print("❌ Errore filtro fmt_it_smart:", e)
        return value

@app.context_processor
def inject_session():
    """Rende disponibile la sessione Flask in tutti i template."""
    from flask import session
    return dict(session=session)


# Imposta tempo di "grazia" (in secondi) dopo la chiusura chat
app.config.setdefault('CHAT_RECENTLY_READ_TTL', 5)
# ---------------------------------------------------------
# Sessioni (Render-friendly)
# ---------------------------------------------------------
from flask_session import Session

app.config['SESSION_TYPE'] = 'filesystem'

# Su Render /tmp è più veloce e sicuro rispetto alla cartella del progetto
session_dir = os.getenv("SESSION_FILE_DIR") or "/tmp/.flask_session"
app.config['SESSION_FILE_DIR'] = session_dir

try:
    os.makedirs(session_dir, exist_ok=True)
except Exception as e:
    # non blocchiamo il boot per un errore filesystem
    print("⚠️ Impossibile creare SESSION_FILE_DIR:", session_dir, e)

Session(app)

print("Percorso database usato:", os.path.abspath('database.db'))


@app.template_filter('safe_strip')
def safe_strip(value):
    return (value or '').strip()

@app.template_filter('datetimeformat')
def datetimeformat(value, fmt='%d %B %Y'):
    """Formatta la data per mostrare solo giorno e mese in italiano."""
    try:
        dt = datetime.fromisoformat(value)
        mesi = [
            "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
            "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"
        ]
        mese_nome = mesi[dt.month - 1]
        return f"{dt.day} {mese_nome} {dt.year}"
    except Exception:
        return value


# 🔹 Configurazione Flask-Mail letta dal file mail.env
app.config['MAIL_SERVER'] = 'smtps.aruba.it'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['MAIL_TIMEOUT'] = 20
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_DEBUG'] = (os.getenv("FLASK_ENV") == "development")

# 🌐 Base URL per generare link assoluti (prod vs locale)
app.config["APP_BASE_URL"] = os.getenv("APP_BASE_URL", "http://127.0.0.1:5000").rstrip("/")

# 🔐 Salt usato per i token di reset password (mettilo anche in mail.env se vuoi)
app.config['SECURITY_PASSWORD_SALT'] = os.getenv(
    'SECURITY_PASSWORD_SALT',
    'metti-qui-una-stringa-lunga-casuale'
)

# 🔹 Inizializza Flask-Mail
mail = Mail(app)
print("APP_BASE_URL =", repr(app.config.get("APP_BASE_URL")))
# ---------------------------------------------------------
# 📧 FUNZIONI EMAIL – UTENTE
# ---------------------------------------------------------
def build_external_url(endpoint: str, **values) -> str:
    base = (app.config.get("APP_BASE_URL") or "").rstrip("/")
    path = url_for(endpoint, _external=False, **values)   # /conferma/<token>
    return f"{base}{path}"

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def get_reset_serializer():
    """Restituisce il serializer firmato per i token di reset password."""
    secret_key = app.config.get('SECRET_KEY') or app.secret_key
    return URLSafeTimedSerializer(secret_key)


def invia_email_sospensione(email, nome):
    try:
        html = render_template(
            "email/sospensione_account.html",
            nome=nome
        )

        msg = Message(
            "Il tuo account MyLocalCare è stato sospeso",
            sender="MyLocalCare <info@mylocalcare.it>",
            recipients=[email]
        )

        msg.html = html
        msg.body = "Il tuo account MyLocalCare è stato sospeso."

        mail.send(msg)

    except Exception as e:
        print("Errore invio email sospensione:", e)
# ==========================================================
# 2️⃣ FUNZIONE CONNESSIONE DB E MODELS
# ==========================================================

class PGCursorWrapper:
    """
    Wrapper del cursor per convertire automaticamente
    i placeholder SQLite (?) in PostgreSQL (%s)
    """

    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, query, params=None):
        query = query.replace("?", "%s")
        self.cursor.execute(query, params or ())
        return self

    def executemany(self, query, params_list):
        query = query.replace("?", "%s")
        return self.cursor.executemany(query, params_list)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class PGConnectionWrapper:
    """
    Wrapper che rende psycopg2 compatibile con stile SQLite.
    Permette di usare conn.execute() ovunque nel codice.
    """

    def __init__(self, conn):
        self.conn = conn

    def execute(self, query, params=None):
        cur = self.conn.cursor()

        # converte placeholder SQLite → Postgres
        query = query.replace("?", "%s")

        cur.execute(query, params or ())
        return cur

    def cursor(self):
        return PGCursorWrapper(self.conn.cursor())

    def commit(self):
        return self.conn.commit()

    def close(self):
        global _pg_pool
        try:
            _pg_pool.putconn(self.conn)
        except Exception:
            try:
                self.conn.close()
            except:
                pass

    def __getattr__(self, name):
        return getattr(self.conn, name)


def get_db_connection():
    global _pg_pool
    from flask import has_request_context

    database_url = os.getenv("DATABASE_URL")
    app.config["IS_POSTGRES"] = bool(database_url)

    # =========================
    # POSTGRES
    # =========================
    if database_url:

        if _pg_pool is None:
            init_pg_pool()

        if has_request_context():
            if hasattr(g, "db_conn") and g.db_conn is not None:
                try:
                    g.db_conn.cursor().execute("SELECT 1")
                    return g.db_conn
                except Exception:
                    try:
                        g.db_conn.close()
                    except:
                        pass
                    g.db_conn = None

        raw = _pg_pool.getconn()

        if raw.closed:
            _pg_pool.putconn(raw, close=True)
            raw = _pg_pool.getconn()

        raw.autocommit = True
        raw.set_session(readonly=False, autocommit=True)

        wrapped = PGConnectionWrapper(raw)

        if has_request_context():
            g.db_conn = wrapped

        return wrapped

    # =========================
    # SQLITE
    # =========================
    else:

        if hasattr(g, "db_conn"):
            return g.db_conn

        import sqlite3

        conn = sqlite3.connect('database.db', timeout=5)
        conn.row_factory = sqlite3.Row

        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")

        g.db_conn = conn
        return conn

def close_db_connection(conn):
    if not conn:
        return
    try:
        conn.close()
    except:
        pass

app.config["DB_CONN_FACTORY"] = get_db_connection
app.config["IS_POSTGRES"] = bool(os.getenv("DATABASE_URL"))


# --- Middleware di protezione per login richiesto ---
def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.utente is None:
            flash("Devi accedere per vedere questa pagina.")
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

from functools import wraps
from flask import redirect, url_for, flash, g

def foto_obbligatoria(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Se non è loggato, si occupa già login_required
        user = g.get("utente")

        if not user:
            flash("Devi essere loggato.", "error")
            return redirect(url_for("login"))

        # ⚠️ Blocco se manca la foto profilo
        if not user["foto_profilo"]:
            flash("Per usare questa funzione devi caricare una foto profilo.", "error")
            return redirect(url_for("dashboard"))  # pagina modifica profilo

        return f(*args, **kwargs)
    return wrapper


# ==========================================================
# 🔹 ADMIN COUNTERS (Annunci e Recensioni in attesa)
# ==========================================================

from threading import Lock
db_lock = Lock()

from functools import wraps

from functools import wraps
from datetime import datetime, timezone

def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        # 1) deve essere loggato
        if not g.utente:
            flash("Devi accedere per entrare nell'area amministratore.", "error")
            return redirect(url_for("login"))

        # g.utente è uno sqlite3.Row
        row = g.utente

        # 2) deve avere ruolo = 'admin'
        ruolo = row["ruolo"] if "ruolo" in row.keys() else None
        if ruolo != "admin":
            flash("Accesso riservato agli amministratori.", "error")
            return redirect(url_for("home"))

        # 3) 🔐 Verifica token di sessione admin
        session_token = session.get("admin_session_token")

        db_token  = row["admin_session_token"]     if "admin_session_token"     in row.keys() else None
        db_expiry = row["admin_session_expiry"]    if "admin_session_expiry"    in row.keys() else None
        db_fp     = row["admin_browser_fingerprint"] if "admin_browser_fingerprint" in row.keys() else None

        # deve esistere un token in sessione
        if not session_token or not db_token:
            flash("Sessione amministratore non valida. Esegui di nuovo il login.", "error")
            session.clear()
            return redirect(url_for("login"))

        # deve coincidere con quello nel database
        if session_token != db_token:
            flash("La sessione amministratore è stata invalidata. Esegui di nuovo il login.", "error")
            session.clear()
            return redirect(url_for("login"))

        # 🔐 Verifica impronta browser
        session_fp = session.get("admin_browser_fingerprint")
        current_fp = request.headers.get("User-Agent", "unknown")

        if not session_fp or not db_fp:
            flash("Sessione amministratore non valida (mancano dati device).", "error")
            session.clear()
            return redirect(url_for("login"))

        # ❌ Se fingerprint diverso → blocco totale
        if session_fp != db_fp or current_fp != db_fp:
            flash("Accesso amministratore bloccato: dispositivo non riconosciuto.", "error")
            session.clear()
            return redirect(url_for("login"))

        # deve essere ancora valido (non scaduto)
        expiry_dt = None
        try:
            if not db_expiry:
                expiry_dt = None
            elif isinstance(db_expiry, datetime):
                expiry_dt = db_expiry
            elif isinstance(db_expiry, str):
                expiry_dt = datetime.fromisoformat(db_expiry)
            else:
                expiry_dt = None

            # se arriva naive, rendilo UTC
            if expiry_dt and expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)

        except Exception as e:
            print("❌ admin_required expiry parse error:", repr(e), "db_expiry=", repr(db_expiry))
            session.clear()
            flash("Sessione non valida (errore token).", "error")
            return redirect(url_for("login"))

        if not expiry_dt or expiry_dt < datetime.now(timezone.utc):
            flash("La sessione amministratore è scaduta. Accedi di nuovo.", "warning")
            session.clear()
            return redirect(url_for("login"))

        # 4) tutto ok → esegui la view
        return view_func(*args, **kwargs)

    return wrapped_view


@app.route("/admin/counters")
@admin_required
def admin_counters():
    cache = app.config["_ADMIN_COUNTERS_CACHE"]
    ttl = app.config["_ADMIN_COUNTERS_TTL"]
    now = time.time()

    # 🔹 Usa la cache se ancora fresca
    if cache["payload"] is not None and (now - cache["ts"] < ttl):
        return jsonify(cache["payload"])

    with db_lock:
        conn = get_db_connection()
        c = get_cursor(conn)
        try:
            # 🟡 Conta annunci in attesa
            c.execute(sql("SELECT COUNT(*) FROM annunci WHERE stato = 'in_attesa'"))
            pending_annunci = fetchone_value(c.fetchone())

            # 🟡 Conta recensioni in attesa
            c.execute(sql("SELECT COUNT(*) FROM recensioni WHERE stato = 'in_attesa'"))
            pending_recensioni = fetchone_value(c.fetchone())

            # 🟡 Conta risposte in attesa
            c.execute(sql("SELECT COUNT(*) FROM risposte_recensioni WHERE stato = 'in_attesa'"))
            pending_risposte = fetchone_value(c.fetchone())

            # ✅ Somma recensioni + risposte nel badge “recensioni”
            pending_recensioni_totali = pending_recensioni + pending_risposte

                        # 🎥 Minuti video usati (mese corrente)
            if app.config.get("IS_POSTGRES"):
                c.execute("""
                    SELECT COALESCE(minuti_totali, 0)
                    FROM video_limiti_mensili
                    WHERE mese = TO_CHAR(NOW(),'YYYY-MM')
                """)
            else:
                c.execute("""
                    SELECT COALESCE(minuti_totali, 0)
                    FROM video_limiti_mensili
                    WHERE mese = {month_sql()}
                """)
            row = c.fetchone()
            video_minuti = list(row.values())[0] if row else 0

        finally:
            try:
                conn.close()
            except:
                pass

    totale = pending_annunci + pending_recensioni_totali
    payload = {
        "annunci": pending_annunci,
        "recensioni": pending_recensioni_totali,
        "risposte": pending_risposte,
        "totale": totale,
        "video_minuti": video_minuti
    }

    cache["payload"] = payload
    cache["ts"] = now
    return jsonify(payload)


# ==========================================================
# NOTIFICHE: LETTURA SINGOLA
# ==========================================================
@app.route('/notifiche/leggi/<int:id>', methods=["GET", "POST"])
@login_required
def leggi_notifica(id):
    segna_notifica_letta(id, g.utente['id'])
    # 🔔 aggiorna il badge in tempo reale
    emit_update_notifications(g.utente['id'])
    flash("Notifica segnata come letta.")
    return redirect(url_for('notifiche'))


# ==========================================================
# ANNUNCI – VISTA SINGOLA + TOGGLE STATO
# ==========================================================
@app.route("/admin/annunci/<int:id>")
@admin_required
def admin_visualizza_annuncio(id):
    conn = get_db_connection()
    c = get_cursor(conn)
    c.execute(sql("""
        SELECT a.*, u.nome, u.cognome, u.email, u.username
        FROM annunci a
        JOIN utenti u ON a.utente_id = u.id
        WHERE a.id = ?
    """), (id,))
    annuncio = c.fetchone()


    if not annuncio:
        return "Annuncio non trovato", 404

    return render_template("admin_visualizza_annuncio.html", annuncio=annuncio)


@app.route("/admin/annunci/toggle/<int:id>")
@admin_required
def toggle_annuncio(id):
    conn = get_db_connection()
    c = get_cursor(conn)
    c.execute(sql("SELECT stato FROM annunci WHERE id = ?"), (id,))
    row = c.fetchone()
    if not row:

        flash("Annuncio non trovato.", "error")
        return redirect(url_for("admin_annunci"))

    nuovo_stato = "disattivato" if row["stato"] == "approvato" else "approvato"
    c.execute(sql("UPDATE annunci SET stato = ? WHERE id = ?"), (nuovo_stato, id))
    conn.commit()


    flash(f"Annuncio {nuovo_stato}.", "info")
    next_url = request.args.get("next")
    if next_url and next_url.startswith("/admin/annunci"):
        return redirect(next_url)

    return redirect(url_for("admin_annunci"))

# ==========================
#   SEZIONI ADMIN COMPLETE
# ==========================

# 🔹 ROOT ADMIN → reindirizza sempre alla dashboard unificata
@app.route("/admin")
@admin_required
def admin():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Dashboard principale operatori"""
    categoria = request.args.get('categoria', '').strip()
    if categoria:
        categoria = categoria.replace("-", " ").replace("%26", "&").strip().lower()

    zona = request.args.get('zona')

    operatori = get_operatori(categoria, zona)
    utenti = get_utenti()

    return render_template(
        "admin_dashboard.html",
        operatori=operatori,
        utenti=utenti,
        categoria=categoria,
        zona=zona
    )

from flask import render_template, request, redirect, url_for, flash
import sqlite3
from datetime import datetime, timedelta
# ==========================================================
# 🎥 ADMIN — VIDEO CALLS STORICO COMPLETO
# ==========================================================
@app.route("/admin/video-calls")
@admin_required
def admin_video_calls():

    conn = get_db_connection()
    cur = get_cursor(conn)

    rows = cur.execute(sql(f"""
        SELECT
            v.*,
            u1.username AS user1_name,
            u2.username AS user2_name,
            {month_sql("v.created_at")} AS mese
        FROM video_call_log v
        LEFT JOIN utenti u1 ON u1.id = v.utente_1
        LEFT JOIN utenti u2 ON u2.id = v.utente_2
        ORDER BY v.created_at DESC
    """)).fetchall()

    limiti = cur.execute(sql("""
        SELECT mese, minuti_totali, costo_totale_cent
        FROM video_limiti_mensili
    """)).fetchall()

    limiti_dict = {l["mese"]: l for l in limiti}



    mesi = {}

    for r in rows:

        mese = r["mese"]

        # 🔹 crea il mese se non esiste
        if mese not in mesi:

            limite = limiti_dict.get(mese)

            used = limite["minuti_totali"] if limite else 0
            costo = limite["costo_totale_cent"] if limite else 0

            mesi[mese] = {
                "calls": [],
                "participant_used": used,
                "participant_remaining": max(0, 10000 - used),
                "costo": costo
            }

        call = dict(r)

        # INIZIO
        if call["created_at"]:
            start_utc = datetime.strptime(call["created_at"], "%Y-%m-%d %H:%M:%S")
            start_local = start_utc + timedelta(hours=1)

            call["start_date"] = start_local.strftime("%d/%m/%Y")
            call["start_time"] = start_local.strftime("%H:%M:%S")
        else:
            call["start_date"] = "-"
            call["start_time"] = "-"

        # FINE
        if call.get("ended_at"):
            end_utc = datetime.strptime(call["ended_at"], "%Y-%m-%d %H:%M:%S")
            end_local = end_utc + timedelta(hours=1)
            call["end_time"] = end_local.strftime("%H:%M:%S")
        else:
            call["end_time"] = "-"

        mesi[mese]["calls"].append(call)

    return render_template(
        "admin_video_calls.html",
        mesi=mesi
    )

# ---------------------------------------------------------
# 💰 ADMIN - SERVIZI (MONETIZZAZIONE) - SOLO CONFIG (STEP 3)
# ---------------------------------------------------------
@app.route("/admin/servizi")
@admin_required
def admin_servizi():
    conn = get_db_connection()

    c = get_cursor(conn)

    c.execute(sql("""
        SELECT id, codice, nome, descrizione, ambito, target,
               durata_default_giorni, ripetibile, attivabile_admin, attivo, created_at
        FROM servizi
        ORDER BY created_at DESC
    """))
    servizi = c.fetchall()


    return render_template(
    "admin_servizi.html",
    servizi=servizi,
    tab="servizi"
)


@app.route("/admin/servizi/nuovo", methods=["GET", "POST"])
@admin_required
def admin_servizi_nuovo():
    if request.method == "POST":
        codice = (request.form.get("codice") or "").strip()
        nome = (request.form.get("nome") or "").strip()
        descrizione = (request.form.get("descrizione") or "").strip()

        ambito = (request.form.get("ambito") or "").strip()
        target = (request.form.get("target") or "").strip()

        durata_raw = (request.form.get("durata_default_giorni") or "").strip()
        durata = int(durata_raw) if durata_raw.isdigit() else None

        ripetibile = 1 if request.form.get("ripetibile") == "1" else 0
        attivabile_admin = 1 if request.form.get("attivabile_admin") == "1" else 0
        attivo = 1 if request.form.get("attivo") == "1" else 0

        # validazioni minime (solo per evitare record rotti)
        allowed_ambiti = {"annuncio", "profilo", "chat", "homepage"}
        allowed_target = {"offre", "cerca", "entrambi"}

        if not codice or not nome:
            flash("Codice e Nome sono obbligatori.", "error")
            return redirect(url_for("admin_servizi_nuovo"))

        if ambito not in allowed_ambiti:
            flash("Ambito non valido.", "error")
            return redirect(url_for("admin_servizi_nuovo"))

        if target not in allowed_target:
            flash("Target non valido.", "error")
            return redirect(url_for("admin_servizi_nuovo"))

        conn = get_db_connection()
        c = get_cursor(conn)
        try:
            c.execute(sql("""
                INSERT INTO servizi
                (codice, nome, descrizione, ambito, target,
                 durata_default_giorni, ripetibile, attivabile_admin, attivo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """), (codice, nome, descrizione, ambito, target,
                  durata, ripetibile, attivabile_admin, attivo))
            conn.commit()
            flash("Servizio creato.", "success")
            return redirect(url_for("admin_servizi"))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Codice già esistente (deve essere univoco).", "error")
            return redirect(url_for("admin_servizi_nuovo"))
        finally:
            try:
                conn.close()
            except:
                pass


    # GET
    return render_template("admin_servizi_form.html", servizio=None)


@app.route("/admin/servizi/<int:id>/modifica", methods=["GET", "POST"])
@admin_required
def admin_servizi_modifica(id):
    conn = get_db_connection()

    c = get_cursor(conn)

    c.execute(sql("SELECT * FROM servizi WHERE id = ?"), (id,))
    servizio = c.fetchone()

    if not servizio:

        flash("Servizio non trovato.", "error")
        return redirect(url_for("admin_servizi"))

    if request.method == "POST":
        codice = (request.form.get("codice") or "").strip()
        nome = (request.form.get("nome") or "").strip()
        descrizione = (request.form.get("descrizione") or "").strip()

        ambito = (request.form.get("ambito") or "").strip()
        target = (request.form.get("target") or "").strip()

        durata_raw = (request.form.get("durata_default_giorni") or "").strip()
        durata = int(durata_raw) if durata_raw.isdigit() else None

        ripetibile = 1 if request.form.get("ripetibile") == "1" else 0
        attivabile_admin = 1 if request.form.get("attivabile_admin") == "1" else 0
        attivo = 1 if request.form.get("attivo") == "1" else 0

        allowed_ambiti = {"annuncio", "profilo", "chat", "homepage"}
        allowed_target = {"offre", "cerca", "entrambi"}

        if not codice or not nome:

            flash("Codice e Nome sono obbligatori.", "error")
            return redirect(url_for("admin_servizi_modifica", id=id))

        if ambito not in allowed_ambiti:

            flash("Ambito non valido.", "error")
            return redirect(url_for("admin_servizi_modifica", id=id))

        if target not in allowed_target:

            flash("Target non valido.", "error")
            return redirect(url_for("admin_servizi_modifica", id=id))

        try:
            c.execute(sql("""
                UPDATE servizi
                SET codice = ?, nome = ?, descrizione = ?,
                    ambito = ?, target = ?,
                    durata_default_giorni = ?,
                    ripetibile = ?, attivabile_admin = ?, attivo = ?
                WHERE id = ?
            """), (codice, nome, descrizione, ambito, target,
                  durata, ripetibile, attivabile_admin, attivo, id))
            conn.commit()
            flash("Servizio aggiornato.", "success")
            return redirect(url_for("admin_servizi"))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Codice già esistente (deve essere univoco).", "error")
            return redirect(url_for("admin_servizi_modifica", id=id))
        finally:
            try:
                conn.close()
            except:
                pass



    return render_template("admin_servizi_form.html", servizio=servizio)


@app.route("/admin/servizi/<int:id>/toggle")
@admin_required
def admin_servizi_toggle(id):
    conn = get_db_connection()

    c = get_cursor(conn)

    c.execute(sql("SELECT attivo FROM servizi WHERE id = ?"), (id,))
    row = c.fetchone()
    if not row:

        flash("Servizio non trovato.", "error")
        return redirect(url_for("admin_servizi"))

    nuovo = 0 if row["attivo"] == 1 else 1
    c.execute(sql("UPDATE servizi SET attivo = ? WHERE id = ?"), (nuovo, id))
    conn.commit()


    flash("Stato servizio aggiornato.", "success")
    return redirect(url_for("admin_servizi"))

@app.route("/admin/servizi/<int:servizio_id>/elimina", methods=["POST"])
@admin_required
def admin_servizi_elimina(servizio_id):
    conn = get_db_connection()
    c = get_cursor(conn)

    c.execute(sql("""
        UPDATE servizi
        SET attivo = 0
        WHERE id = ?
    """), (servizio_id,))

    conn.commit()


    flash("Servizio disattivato correttamente.", "success")
    return redirect(url_for("admin_servizi"))

@app.route("/admin/toggle-servizio", methods=["POST"])
@admin_required
def admin_toggle_servizio():
    verify_csrf()

    data = request.get_json(silent=True) or {}

    codice_servizio = (data.get("codice_servizio") or "").strip()
    annuncio_id = data.get("annuncio_id")
    utente_id = data.get("utente_id")

    if not codice_servizio or not utente_id:
        return jsonify({"ok": False, "error": "Parametri mancanti"}), 400

    conn = get_db_connection()


    try:
        # 1️⃣ servizio
        servizio = conn.execute(sql("""
            SELECT id, ambito, attivo
            FROM servizi
            WHERE codice = ?
            LIMIT 1
        """), (codice_servizio,)).fetchone()

        if not servizio or servizio["attivo"] != 1:
            return jsonify({"ok": False, "error": "Servizio non valido o disattivo"}), 400

        ambito = servizio["ambito"]

        # 2️⃣ cerca attivazione attiva
        if ambito == "annuncio":

            if not annuncio_id:
                return jsonify({"ok": False, "error": "annuncio_id obbligatorio"}), 400

            attiva = conn.execute(sql(f"""
                SELECT id
                FROM attivazioni_servizi
                WHERE servizio_id = ?
                  AND annuncio_id = ?
                  AND stato = 'attivo'
                  AND data_inizio <= {now_sql()}
                  AND (data_fine IS NULL OR data_fine > {now_sql()})
                LIMIT 1
            """), (servizio["id"], annuncio_id)).fetchone()

        else:

            attiva = conn.execute(sql(f"""
                SELECT id
                FROM attivazioni_servizi
                WHERE servizio_id = ?
                  AND utente_id = ?
                  AND annuncio_id IS NULL
                  AND stato = 'attivo'
                  AND data_inizio <= {now_sql()}
                  AND (data_fine IS NULL OR data_fine > {now_sql()})
                LIMIT 1
            """), (servizio["id"], utente_id)).fetchone()

        # 3️⃣ toggle
        if attiva:
            ok, msg = revoca_attivazione(attiva["id"], eseguito_da="admin")

            return jsonify({
                "ok": ok,
                "azione": "disattivato",
                "messaggio": msg
            })
        else:
            ok, msg, att_id = attiva_servizio(
                utente_id=int(utente_id),
                codice_servizio=codice_servizio,
                annuncio_id=int(annuncio_id) if ambito == "annuncio" else None,
                attivato_da="admin",
                note="Attivazione manuale admin"
            )

            # 🔔 NOTIFICA URGENTE — SOLO SE HA SENSO
            if ok and codice_servizio == "annuncio_urgente" and annuncio_id:
                try:
                    notifica_urgente(
                        annuncio_id=int(annuncio_id),
                        attivazione_id=att_id,
                        eseguito_da="admin"
                    )
                except Exception as e:
                    # ⚠️ Non blocca il toggle se la notifica fallisce
                    print(f"⚠️ Errore notifica urgente: {e}")


            return jsonify({
                "ok": ok,
                "azione": "attivato",
                "messaggio": msg,
                "attivazione_id": att_id
            })

    except Exception as e:

        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/admin/servizi/<int:servizio_id>/piani")
@admin_required
def admin_servizi_piani(servizio_id):
    conn = get_db_connection()


    servizio = conn.execute(sql("""
        SELECT id, codice, nome
        FROM servizi
        WHERE id = ?
    """), (servizio_id,)).fetchone()

    if not servizio:

        flash("Servizio non trovato.", "error")
        return redirect(url_for("admin_servizi"))

    piani = conn.execute(sql("""
        SELECT *
        FROM servizi_piani
        WHERE servizio_id = ?
        ORDER BY ordine ASC, durata_giorni ASC
    """), (servizio_id,)).fetchall()



    return render_template(
        "admin_servizi_piani.html",
        servizio=servizio,
        piani=piani
    )

# ===============================
# 📦 LISTA PACCHETTI
# ===============================
@app.route("/admin/pacchetti")
@admin_required
def admin_pacchetti():
    conn = get_db_connection()


    pacchetti = conn.execute(sql("""
        SELECT *
        FROM pacchetti
        ORDER BY created_at DESC
    """)).fetchall()



    return render_template(
        "admin_pacchetti.html",
        pacchetti=pacchetti,
        tab="pacchetti"
    )


# ===============================
# ➕ NUOVO PACCHETTO
# ===============================
@app.route("/admin/pacchetti/nuovo", methods=["GET", "POST"])
@admin_required
def admin_pacchetti_nuovo():
    conn = get_db_connection()


    servizi = conn.execute(sql("""
        SELECT id, codice, nome
        FROM servizi
        WHERE attivo = 1
        ORDER BY nome
    """)).fetchall()

    if request.method == "POST":
        codice = request.form.get("codice")
        nome = request.form.get("nome")
        descrizione = request.form.get("descrizione")
        attivo = 1 if request.form.get("attivo") else 0
        servizi_selezionati = request.form.getlist("servizi")

        cur = get_cursor(conn)

        pacchetto_id = insert_and_get_id(
            cur,
            """
            INSERT INTO pacchetti (codice, nome, descrizione, attivo)
            VALUES (?, ?, ?, ?)
            """,
            (codice, nome, descrizione, attivo)
        )

        for sid in servizi_selezionati:
            cur.execute(sql("""
                INSERT INTO pacchetti_servizi (pacchetto_id, servizio_id)
                VALUES (?, ?)
            """), (pacchetto_id, sid))

        conn.commit()


        flash("Pacchetto creato.", "success")
        return redirect(url_for("admin_pacchetti"))


    return render_template(
        "admin_pacchetti_form.html",
        pacchetto=None,
        servizi=servizi,
        servizi_attivi=[],
        tab="pacchetti"
    )


# ===============================
# ✏️ MODIFICA PACCHETTO
# ===============================
@app.route("/admin/pacchetti/<int:id>/modifica", methods=["GET", "POST"])
@admin_required
def admin_pacchetti_modifica(id):
    conn = get_db_connection()

    pacchetto = conn.execute(
        sql("SELECT * FROM pacchetti WHERE id = ?"),
        (id,)
    ).fetchone()

    if not pacchetto:
        flash("Pacchetto non trovato.", "error")
        return redirect(url_for("admin_pacchetti"))

    servizi = conn.execute(
        sql("""
            SELECT id, codice, nome
            FROM servizi
            WHERE attivo = 1
            ORDER BY nome
        """)
    ).fetchall()

    servizi_attivi = [
        r["servizio_id"]
        for r in conn.execute(
            sql("""
                SELECT servizio_id
                FROM pacchetti_servizi
                WHERE pacchetto_id = ?
            """),
            (id,)
        ).fetchall()
    ]

    if request.method == "POST":
        codice = request.form.get("codice")
        nome = request.form.get("nome")
        descrizione = request.form.get("descrizione")
        attivo = 1 if request.form.get("attivo") else 0
        servizi_selezionati = request.form.getlist("servizi")

        cur = get_cursor(conn)

        # UPDATE pacchetto
        cur.execute(
            sql("""
                UPDATE pacchetti
                SET codice = ?, nome = ?, descrizione = ?, attivo = ?
                WHERE id = ?
            """),
            (codice, nome, descrizione, attivo, id)
        )

        # RESET servizi collegati
        cur.execute(
            sql("DELETE FROM pacchetti_servizi WHERE pacchetto_id = ?"),
            (id,)
        )

        # RE-INSERIMENTO servizi selezionati
        for sid in servizi_selezionati:
            cur.execute(
                sql("""
                    INSERT INTO pacchetti_servizi (pacchetto_id, servizio_id)
                    VALUES (?, ?)
                """),
                (id, sid)
            )

        conn.commit()

        flash("Pacchetto aggiornato.", "success")
        return redirect(url_for("admin_pacchetti"))

    return render_template(
        "admin_pacchetti_form.html",
        pacchetto=pacchetto,
        servizi=servizi,
        servizi_attivi=servizi_attivi,
        tab="pacchetti"
    )

# ===============================
# 🔁 TOGGLE PACCHETTO
# ===============================
@app.route("/admin/pacchetti/<int:id>/toggle")
@admin_required
def admin_toggle_pacchetto_tabella(id):
    conn = get_db_connection()

    conn.execute(sql("""
        UPDATE pacchetti
        SET attivo = CASE WHEN attivo = 1 THEN 0 ELSE 1 END
        WHERE id = ?
    """), (id,))

    conn.commit()


    flash("Stato pacchetto aggiornato.", "success")
    return redirect(url_for("admin_pacchetti"))

# ===============================
# ➕ NUOVO PIANO SERVIZIO
# ===============================
@app.route("/admin/servizi/<int:servizio_id>/piani/nuovo", methods=["GET", "POST"])
@admin_required
def admin_servizi_piani_nuovo(servizio_id):
    conn = get_db_connection()


    servizio = conn.execute(
        "SELECT id, nome FROM servizi WHERE id = ?",
        (servizio_id,)
    ).fetchone()

    if not servizio:

        flash("Servizio non trovato.", "error")
        return redirect(url_for("admin_servizi"))

    if request.method == "POST":
        # 🔢 durata: numero o permanente (NULL)
        if request.form.get("permanente"):
            durata_giorni = None
        else:
            durata_giorni = int(request.form.get("durata_giorni"))

        # 💶 conversione € → cent
        prezzo_euro_raw = request.form.get("prezzo_euro", "0").replace(",", ".")
        prezzo_cent = int(round(float(prezzo_euro_raw) * 100))

        data = (
            servizio_id,
            request.form.get("codice"),
            request.form.get("nome"),
            request.form.get("descrizione"),
            durata_giorni,
            prezzo_cent,
            int(request.form.get("ordine", 1)),
            1 if request.form.get("evidenziato") else 0,
            1 if request.form.get("consigliato") else 0,
            1 if request.form.get("attivo") else 0,
        )

        try:
            conn.execute(sql("""
                INSERT INTO servizi_piani
                (servizio_id, codice, nome, descrizione,
                 durata_giorni, prezzo_cent, ordine,
                 evidenziato, consigliato, attivo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """), data)
            conn.commit()
            flash("Piano creato.", "success")
            return redirect(
                url_for("admin_servizi_piani", servizio_id=servizio_id)
            )
        except sqlite3.IntegrityError:
            flash("Codice piano già esistente per questo servizio.", "error")


    return render_template(
        "admin_servizi_piani_form.html",
        servizio=servizio,
        piano=None
    )


# ===============================
# ✏️ MODIFICA PIANO SERVIZIO
# ===============================
@app.route("/admin/servizi/piani/<int:piano_id>/modifica", methods=["GET", "POST"])
@admin_required
def admin_servizi_piani_modifica(piano_id):
    conn = get_db_connection()


    piano = conn.execute(sql("""
        SELECT p.*, s.nome AS servizio_nome
        FROM servizi_piani p
        JOIN servizi s ON s.id = p.servizio_id
        WHERE p.id = ?
    """), (piano_id,)).fetchone()

    if not piano:

        flash("Piano non trovato.", "error")
        return redirect(url_for("admin_servizi"))

    if request.method == "POST":
        # 🔢 durata: numero o permanente (NULL)
        if request.form.get("permanente"):
            durata_giorni = None
        else:
            durata_giorni = int(request.form.get("durata_giorni"))

        # 💶 conversione € → cent
        prezzo_euro_raw = request.form.get("prezzo_euro", "0").replace(",", ".")
        prezzo_cent = int(round(float(prezzo_euro_raw) * 100))

        conn.execute(sql("""
            UPDATE servizi_piani
            SET codice = ?, nome = ?, descrizione = ?,
                durata_giorni = ?, prezzo_cent = ?, ordine = ?,
                evidenziato = ?, consigliato = ?, attivo = ?
            WHERE id = ?
        """), (
            request.form.get("codice"),
            request.form.get("nome"),
            request.form.get("descrizione"),
            durata_giorni,
            prezzo_cent,
            int(request.form.get("ordine", 1)),
            1 if request.form.get("evidenziato") else 0,
            1 if request.form.get("consigliato") else 0,
            1 if request.form.get("attivo") else 0,
            piano_id
        ))

        conn.commit()

        flash("Piano aggiornato.", "success")
        return redirect(
            url_for("admin_servizi_piani", servizio_id=piano["servizio_id"])
        )


    return render_template(
        "admin_servizi_piani_form.html",
        servizio={
            "id": piano["servizio_id"],
            "nome": piano["servizio_nome"]
        },
        piano=piano
    )

@app.route("/admin/servizi/piani/<int:piano_id>/toggle")
@admin_required
def admin_servizi_piani_toggle(piano_id):
    conn = get_db_connection()

    conn.execute(sql("""
        UPDATE servizi_piani
        SET attivo = CASE WHEN attivo = 1 THEN 0 ELSE 1 END
        WHERE id = ?
    """), (piano_id,))

    conn.commit()


    flash("Stato piano aggiornato.", "success")
    return redirect(request.referrer or url_for("admin_servizi"))

PACCHETTI = {
    "pacchetto_visibilita": [
        "boost_lista",
        "badge_evidenza",
        "contatti",
    ],
    "pacchetto_premium": [
        "boost_lista",
        "vetrina_annuncio",
        "badge_evidenza",
        "contatti",
    ],
}

@app.route("/admin/toggle-pacchetto", methods=["POST"])
@admin_required
def admin_toggle_pacchetto():
    verify_csrf()

    data = request.get_json(silent=True) or {}

    codice_pacchetto = (data.get("codice_pacchetto") or "").strip()
    utente_id = data.get("utente_id")
    annuncio_id = data.get("annuncio_id")

    if not codice_pacchetto or not utente_id:
        return jsonify({"ok": False, "error": "Parametri mancanti"}), 400

    if codice_pacchetto not in PACCHETTI:
        return jsonify({"ok": False, "error": "Pacchetto non valido"}), 400

    servizi_pacchetto = PACCHETTI[codice_pacchetto]

    conn = get_db_connection()


    try:
        # =========================
        # 1️⃣ verifica se il pacchetto è già attivo
        # (basta che UNO dei servizi sia attivo)
        # =========================
        pacchetto_attivo = False
        attivazioni_attive = []

        for codice_servizio in servizi_pacchetto:
            servizio = conn.execute(sql("""
                SELECT id, ambito
                FROM servizi
                WHERE codice = ?
                  AND attivo = 1
            """), (codice_servizio,)).fetchone()

            if not servizio:
                continue

            ambito = servizio["ambito"]

            if ambito == "annuncio":
                row = conn.execute(sql(f"""
                    SELECT id
                    FROM attivazioni_servizi
                    WHERE servizio_id = ?
                      AND annuncio_id = ?
                      AND stato = 'attivo'
                      AND data_inizio <= {now_sql()}
                      AND (data_fine IS NULL OR data_fine > {now_sql()})
                    LIMIT 1
                """), (servizio["id"], annuncio_id)).fetchone()
            else:
                row = conn.execute(sql(f"""
                    SELECT id
                    FROM attivazioni_servizi
                    WHERE servizio_id = ?
                      AND utente_id = ?
                      AND annuncio_id IS NULL
                      AND stato = 'attivo'
                      AND data_inizio <= {now_sql()}
                      AND (data_fine IS NULL OR data_fine > {now_sql()})
                    LIMIT 1
                """), (servizio["id"], utente_id)).fetchone()

            if row:
                pacchetto_attivo = True
                attivazioni_attive.append(row["id"])

        # =========================
        # 2️⃣ SE ATTIVO → REVOCA
        # =========================
        if pacchetto_attivo:
            for att_id in attivazioni_attive:
                revoca_attivazione(
                    attivazione_id=att_id,
                    eseguito_da="admin",
                    note=f"Revoca pacchetto {codice_pacchetto}"
                )


            return jsonify({
                "ok": True,
                "azione": "disattivato",
                "pacchetto": codice_pacchetto
            })

        # =========================
        # 3️⃣ SE NON ATTIVO → ATTIVA TUTTI I SERVIZI
        # =========================
        attivati = []

        for codice_servizio in servizi_pacchetto:
            ok, msg, att_id = attiva_servizio(
                utente_id=int(utente_id),
                codice_servizio=codice_servizio,
                annuncio_id=int(annuncio_id) if annuncio_id else None,
                attivato_da="admin",
                note=f"Attivazione tramite pacchetto {codice_pacchetto}"
            )

            if ok:
                attivati.append(att_id)


        return jsonify({
            "ok": True,
            "azione": "attivato",
            "pacchetto": codice_pacchetto,
            "attivazioni": attivati
        })

    except Exception as e:

        return jsonify({"ok": False, "error": str(e)}), 500

# ===============================
# 📦 LISTA PIANI PACCHETTO
# ===============================
@app.route("/admin/pacchetti/<int:pacchetto_id>/piani")
@admin_required
def admin_pacchetti_piani(pacchetto_id):
    conn = get_db_connection()


    pacchetto = conn.execute(
        "SELECT id, nome FROM pacchetti WHERE id = ?",
        (pacchetto_id,)
    ).fetchone()

    if not pacchetto:

        flash("Pacchetto non trovato.", "error")
        return redirect(url_for("admin_pacchetti"))

    piani = conn.execute(sql("""
        SELECT *
        FROM pacchetti_piani
        WHERE pacchetto_id = ?
        ORDER BY ordine ASC, created_at ASC
    """), (pacchetto_id,)).fetchall()



    return render_template(
        "admin_pacchetti_piani.html",
        pacchetto=pacchetto,
        piani=piani
    )

# ===============================
# ➕ NUOVO PIANO PACCHETTO
# ===============================
@app.route("/admin/pacchetti/<int:pacchetto_id>/piani/nuovo", methods=["GET", "POST"])
@admin_required
def admin_pacchetti_piani_nuovo(pacchetto_id):
    conn = get_db_connection()


    pacchetto = conn.execute(
        "SELECT id, nome FROM pacchetti WHERE id = ?",
        (pacchetto_id,)
    ).fetchone()

    if not pacchetto:

        flash("Pacchetto non trovato.", "error")
        return redirect(url_for("admin_pacchetti"))

    if request.method == "POST":
        durata = None if request.form.get("permanente") else int(request.form["durata_giorni"])
        prezzo_cent = int(round(float(request.form["prezzo_euro"].replace(",", ".")) * 100))

        data = (
            pacchetto_id,
            request.form["codice"],
            request.form["nome"],
            request.form.get("descrizione"),
            durata,
            prezzo_cent,
            int(request.form.get("ordine", 1)),
            1 if request.form.get("evidenziato") else 0,
            1 if request.form.get("consigliato") else 0,
            1 if request.form.get("attivo") else 0,
        )

        try:
            conn.execute(sql("""
                INSERT INTO pacchetti_piani
                (pacchetto_id, codice, nome, descrizione,
                 durata_giorni, prezzo_cent, ordine,
                 evidenziato, consigliato, attivo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """), data)
            conn.commit()
            flash("Piano pacchetto creato.", "success")
            return redirect(url_for("admin_pacchetti_piani", pacchetto_id=pacchetto_id))
        except sqlite3.IntegrityError:
            flash("Codice piano già esistente per questo pacchetto.", "error")


    return render_template(
        "admin_pacchetti_piani_form.html",
        pacchetto=pacchetto,
        piano=None
    )

# ===============================
# ✏️ MODIFICA PIANO PACCHETTO
# ===============================
@app.route("/admin/pacchetti/piani/<int:id>/modifica", methods=["GET", "POST"])
@admin_required
def admin_pacchetti_piani_modifica(id):
    conn = get_db_connection()


    piano = conn.execute(
        "SELECT * FROM pacchetti_piani WHERE id = ?",
        (id,)
    ).fetchone()

    if not piano:

        flash("Piano non trovato.", "error")
        return redirect(url_for("admin_pacchetti"))

    pacchetto = conn.execute(
        "SELECT id, nome FROM pacchetti WHERE id = ?",
        (piano["pacchetto_id"],)
    ).fetchone()

    if request.method == "POST":
        durata = None if request.form.get("permanente") else int(request.form["durata_giorni"])
        prezzo_cent = int(round(float(request.form["prezzo_euro"].replace(",", ".")) * 100))

        conn.execute(sql("""
            UPDATE pacchetti_piani
            SET codice = ?, nome = ?, descrizione = ?,
                durata_giorni = ?, prezzo_cent = ?, ordine = ?,
                evidenziato = ?, consigliato = ?, attivo = ?
            WHERE id = ?
        """), (
            request.form["codice"],
            request.form["nome"],
            request.form.get("descrizione"),
            durata,
            prezzo_cent,
            int(request.form.get("ordine", 1)),
            1 if request.form.get("evidenziato") else 0,
            1 if request.form.get("consigliato") else 0,
            1 if request.form.get("attivo") else 0,
            id
        ))
        conn.commit()
        flash("Piano aggiornato.", "success")
        return redirect(url_for("admin_pacchetti_piani", pacchetto_id=pacchetto["id"]))


    return render_template(
        "admin_pacchetti_piani_form.html",
        pacchetto=pacchetto,
        piano=piano
    )

# ===============================
# 🔁 TOGGLE ATTIVO PIANO PACCHETTO
# ===============================
@app.route("/admin/pacchetti/piani/<int:piano_id>/toggle")
@admin_required
def admin_pacchetti_piani_toggle(piano_id):
    conn = get_db_connection()


    piano = conn.execute(
        "SELECT id, pacchetto_id, attivo FROM pacchetti_piani WHERE id = ?",
        (piano_id,)
    ).fetchone()

    if not piano:

        flash("Piano non trovato.", "error")
        return redirect(url_for("admin_pacchetti"))

    nuovo_stato = 0 if piano["attivo"] else 1

    conn.execute(
        "UPDATE pacchetti_piani SET attivo = ? WHERE id = ?",
        (nuovo_stato, piano_id)
    )
    conn.commit()


    flash("Stato piano aggiornato.", "success")
    return redirect(
        url_for("admin_pacchetti_piani", pacchetto_id=piano["pacchetto_id"])
    )

# ==========================================================
# GESTIONE UTENTI
# ==========================================================
@app.route('/admin/toggle_utente/<int:id>')
@admin_required
def toggle_utente(id):
    conn = get_db_connection()
    cur = get_cursor(conn)
    cur.execute(sql("SELECT attivo FROM utenti WHERE id = ?"), (id,))
    user = cur.fetchone()
    if user:
        nuovo_stato = 0 if user['attivo'] else 1
        conn.execute(sql("UPDATE utenti SET attivo = ? WHERE id = ?"), (nuovo_stato, id))
        conn.commit()
        flash("Utente {} correttamente.".format("disattivato" if nuovo_stato == 0 else "attivato"))

    return redirect(url_for('admin'))


@app.route('/admin/elimina_utente/<int:id>')
@admin_required
def elimina_utente_route(id):
    elimina_utente(id)
    flash("Utente eliminato correttamente.")
    return redirect(url_for('admin'))


# ==========================================================
# GESTIONE OPERATORI (vecchio pannello)
# ==========================================================
@app.route('/admin/nuovo', methods=['GET', 'POST'])
@admin_required
def admin_nuovo():
    if request.method == 'POST':
        nome = request.form['nome']
        categoria = request.form['categoria']
        zona = request.form['zona']
        servizi = request.form['servizi']
        prezzo = request.form['prezzo']
        bio = request.form['bio']
        filtri = request.form.getlist('filtri_categoria')
        filtri_str = ", ".join(filtri)
        aggiungi_operatore(nome, categoria, zona, servizi, prezzo, bio, filtri_str)
        return redirect(url_for('admin'))
    return redirect(url_for('admin'))


@app.route('/admin/modifica/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_modifica(id):
    operatore = get_operatore_by_id(id)
    if not operatore:
        return "Operatore non trovato", 404

    if request.method == 'POST':
        nome = request.form['nome']
        categoria = request.form['categoria']
        zona = request.form['zona']
        servizi = request.form['servizi']
        prezzo = request.form['prezzo']
        bio = request.form['bio']
        filtri = request.form.getlist('filtri_categoria')
        filtri_str = ", ".join(filtri)
        modifica_operatore(id, nome, categoria, zona, servizi, prezzo, bio, filtri_str)
        return redirect(url_for("admin", successo_modifica=True))

    operatore = dict(operatore)
    operatore["filtri_categoria"] = [
        f.strip() for f in operatore.get("filtri_categoria", "").split(",") if f.strip()
    ]
    return render_template('modifica_operatore.html', operatore=operatore, successo=False)


# ==========================================================
# ADMIN – LISTA UTENTI AVANZATA
# ==========================================================
@app.route("/admin/utenti")
@admin_required
def admin_utenti():
    """Elenco utenti registrati con filtri"""

    nome = request.args.get("nome", "").strip() or ""
    email = request.args.get("email", "").strip() or ""
    citta = request.args.get("citta", "").strip() or ""
    provincia = request.args.get("provincia", "").strip() or ""
    stato = request.args.get("stato", "").strip() or ""

    has_filters = any([nome, email, citta, provincia, stato])

    conn = get_db_connection()

    c = get_cursor(conn)

    c.execute(sql("SELECT COUNT(*) FROM utenti"))
    totale_utenti = fetchone_value(c.fetchone())

    query = f"""
        SELECT
            u.id,
            u.nome,
            u.cognome,
            u.citta,
            u.provincia,
            u.email,
            u.username,
            u.attivo,
            u.sospeso,

            (
              SELECT 1
              FROM attivazioni_servizi a
              JOIN servizi s ON s.id = a.servizio_id
              WHERE a.utente_id = u.id
                AND s.codice = 'contatti'
                AND a.stato = 'attivo'
                AND a.data_inizio <= {now_sql()}
                AND (a.data_fine IS NULL OR a.data_fine > {now_sql()})
              LIMIT 1
            ) AS contatti_attivi

        FROM utenti u
        WHERE 1=1
    """
    params = []

    if nome:
        query += " AND (LOWER(nome) LIKE ? OR LOWER(cognome) LIKE ?)"
        like = f"%{nome.lower()}%"
        params.extend([like, like])

    if email:
        query += " AND LOWER(email) LIKE ?"
        params.append(f"%{email.lower()}%")

    if citta:
        query += " AND LOWER(citta) LIKE ?"
        params.append(f"%{citta.lower()}%")

    if provincia:
        query += " AND LOWER(provincia) LIKE ?"
        params.append(f"%{provincia.lower()}%")

    if stato == "attivo":
        query += " AND attivo = 1 AND sospeso = 0"
    elif stato == "sospeso":
        query += " AND sospeso = 1"
    elif stato == "non_attivo":
        query += " AND attivo = 0"

    query += " ORDER BY cognome ASC, nome ASC"

    c.execute(sql(query), params)
    utenti = c.fetchall()
    totale_filtrati = len(utenti)



    return render_template(
        "admin_utenti.html",
        utenti=utenti,
        nome=nome,
        email=email,
        citta=citta,
        provincia=provincia,
        stato=stato,
        totale_utenti=totale_utenti,
        totale_filtrati=totale_filtrati,
        has_filters=has_filters
    )

@app.route("/admin/utenti/toggle/<int:id>")
@admin_required
def toggle_utente_admin(id):
    conn = get_db_connection()
    c = get_cursor(conn)

    c.execute(sql("SELECT attivo, sospeso FROM utenti WHERE id = ?"), (id,))
    row = c.fetchone()

    if not row:

        flash("Utente non trovato.", "error")
        return redirect(url_for('admin_utenti'))

    attivo, sospeso = row["attivo"], row["sospeso"]

    # 🔄 LOGICA DI ATTIVAZIONE:
    # • Se sospeso → NON può essere attivato
    # • Se attivo → disattiva
    # • Se non attivo → attiva
    if sospeso == 1:
        flash("Impossibile attivare un utente sospeso.", "error")
    else:
        nuovo_stato = 0 if attivo == 1 else 1
        c.execute(sql("UPDATE utenti SET attivo = ? WHERE id = ?"), (nuovo_stato, id))
        conn.commit()

        flash("Stato utente aggiornato.", "success")


    return redirect(url_for("admin_utenti"))

# ==========================================================
# ADMIN – RECENSIONI E RISPOSTE
# ==========================================================
@app.route("/admin/recensioni")
@admin_required
def admin_recensioni():
    """Gestione recensioni e relative risposte con filtri"""
    from models import get_tutte_recensioni_con_risposte

    autore = (request.args.get("autore") or "").strip().lower()
    destinatario = (request.args.get("destinatario") or "").strip().lower()
    voto = (request.args.get("voto") or "").strip()
    stato = (request.args.get("stato") or "").strip().lower()

    try:
        recensioni = get_tutte_recensioni_con_risposte()
    except Exception as e:
        print("Errore caricando recensioni:", e)
        recensioni = []

    recensioni_dict = []
    for r in recensioni:
        if isinstance(r, dict):
            recensioni_dict.append(r)
        else:
            try:
                recensioni_dict.append(dict(r))
            except Exception:
                recensioni_dict.append(r)

    def match(r):
        ok = True

        if autore:
            nome_autore = f"{(r.get('autore_nome') or '').lower()} {(r.get('autore_cognome') or '').lower()}"
            ok = ok and (autore in nome_autore)

        if destinatario:
            nome_dest = f"{(r.get('dest_nome') or '').lower()} {(r.get('dest_cognome') or '').lower()}"
            ok = ok and (destinatario in nome_dest)

        if voto:
            try:
                ok = ok and str(int(voto)) == str(r.get("voto"))
            except Exception:
                return False

        if stato:
            ok = ok and (str(r.get("stato") or "").lower() == stato)

        return ok

    recensioni_filtrate = [r for r in recensioni_dict if match(r)]

    return render_template(
        "admin_recensioni.html",
        recensioni=recensioni_filtrate,
        active_page="recensioni"
    )

from datetime import datetime, timedelta
@app.route("/admin/acquisti")
@login_required
@admin_required
def admin_acquisti():
    conn = get_db_connection()


    rows = conn.execute(sql(f"""
        SELECT
            a.id            AS acquisto_id,
            a.tipo,
            a.importo_cent,
            a.metodo,
            a.stato,
            a.created_at,
            a.annuncio_id,

            u.id            AS utente_id,
            u.email,

            -- nome servizio (se servizio)
            s.nome          AS servizio_nome,

            -- nome pacchetto (se pacchetto)
            p.nome          AS pacchetto_nome,

            -- stato calcolato
            CASE
                WHEN EXISTS (
                    SELECT 1
                    FROM attivazioni_servizi at
                    WHERE at.acquisto_id = a.id
                      AND at.stato = 'attivo'
                      AND (at.data_fine IS NULL OR at.data_fine > {now_sql()})
                )
                THEN 1
                ELSE 0
            END AS stato_attivo,

            (
                SELECT MAX(data_fine)
                FROM attivazioni_servizi
                WHERE acquisto_id = a.id
            ) AS data_fine,

            (
                SELECT COUNT(*)
                FROM attivazioni_servizi
                WHERE acquisto_id = a.id
            ) AS numero_attivazioni

        FROM acquisti a
        JOIN utenti u
          ON u.id = a.utente_id

        -- servizio (solo se tipo servizio)
        LEFT JOIN servizi s
          ON a.tipo = 'servizio'
         AND s.id = (
             SELECT servizio_id
             FROM attivazioni_servizi
             WHERE acquisto_id = a.id
             LIMIT 1
         )

        -- pacchetto
        LEFT JOIN pacchetti p
          ON a.tipo = 'pacchetto'
         AND p.id = a.ref_id

        WHERE a.stato IN ('creato', 'pending', 'paid')
        ORDER BY a.created_at DESC
        LIMIT 500
    """)).fetchall()



    # ✅ CONVERSIONE UTC → ORA ITALIANA
    acquisti = []

    for r in rows:
        row = dict(r)

        if row["created_at"]:
            created_utc = datetime.strptime(row["created_at"], "%Y-%m-%d %H:%M:%S")
            created_local = created_utc + timedelta(hours=1)
            row["created_at"] = created_local.strftime("%Y-%m-%d %H:%M:%S")

        acquisti.append(row)

    return render_template(
        "admin_acquisti.html",
        acquisti=acquisti,
        tab="acquisti"
    )

# ==========================================================
# ADMIN – STATISTICHE
# ==========================================================
@app.route("/admin/statistiche")
@admin_required
def admin_statistiche():
    conn = get_db_connection()

    c = get_cursor(conn)

    c.execute(sql("SELECT COUNT(*) FROM utenti WHERE attivo = 1"))
    utenti_attivi = fetchone_value(c.fetchone())

    c.execute(sql("SELECT COUNT(*) FROM annunci"))
    annunci_totali = fetchone_value(c.fetchone())

    c.execute(sql("SELECT COUNT(DISTINCT utente_id) FROM annunci"))
    utenti_con_annunci = fetchone_value(c.fetchone())

    c.execute(sql("""
        SELECT COUNT(*)
        FROM utenti
        WHERE id NOT IN (SELECT DISTINCT utente_id FROM annunci)
    """))
    utenti_senza_annunci = fetchone_value(c.fetchone())

    c.execute(sql("""
        SELECT COUNT(DISTINCT id_destinatario)
        FROM recensioni
    """))
    utenti_recensiti = fetchone_value(c.fetchone())

    c.execute(sql("""
        SELECT COUNT(*)
        FROM (
            SELECT
                CASE
                    WHEN mittente_id < destinatario_id THEN mittente_id
                    ELSE destinatario_id
                END AS a,
                CASE
                    WHEN mittente_id > destinatario_id THEN mittente_id
                    ELSE destinatario_id
                END AS b
            FROM messaggi_chat
            GROUP BY a, b
        )
    """))
    chat_totali = fetchone_value(c.fetchone())



    return render_template(
        "admin_statistiche.html",
        utenti_attivi=utenti_attivi,
        annunci_totali=annunci_totali,
        utenti_con_annunci=utenti_con_annunci,
        utenti_senza_annunci=utenti_senza_annunci,
        utenti_recensiti=utenti_recensiti,
        chat_totali=chat_totali
    )


# ==========================================================
# ADMIN – NOTIFICHE DI SISTEMA
# ==========================================================
@app.route("/admin/notifiche", methods=["GET", "POST"])
@admin_required
def admin_notifiche():
    """Gestione parametri del sistema notifiche"""
    ttl_corrente = app.config.get("NOTIFICHE_TTL_GIORNI", 10)

    if request.method == "POST":
        nuovo_ttl = request.form.get("scadenza_giorni", type=int)
        if nuovo_ttl and nuovo_ttl > 0:
            app.config["NOTIFICHE_TTL_GIORNI"] = nuovo_ttl
            flash(f"Durata notifiche lette impostata a {nuovo_ttl} giorni ✅", "success")
        else:
            flash("Valore non valido. Inserisci un numero positivo.", "warning")
        return redirect(url_for("admin_notifiche"))

    conn = get_db_connection()

    stats = conn.execute(sql("""
        SELECT
            COUNT(*) AS totali,
            SUM(CASE WHEN letta = 0 THEN 1 ELSE 0 END) AS non_lette,
            SUM(CASE WHEN letta = 1 THEN 1 ELSE 0 END) AS lette
        FROM notifiche
    """)).fetchone()

    # ✅ STORICO NOTIFICHE INVIATE DALL’ADMIN
    notifiche_admin = conn.execute(sql(f"""
        SELECT
            id,
            titolo,
            messaggio,
            link,
            tipo_invio,
            tab_attivo,
            filtro_json,
            destinatari_count,
            destinatari_json,
            created_at
        FROM notifiche_admin
        ORDER BY {order_datetime("created_at")} DESC
        LIMIT 50
    """)).fetchall()

    # ✅ lista utenti (per selezione multipla)
    utenti = conn.execute(sql("""
        SELECT id, nome, cognome, email, username
        FROM utenti
        WHERE sospeso = 0 AND attivo = 1
        ORDER BY nome, cognome
    """)).fetchall()



    # ✅ categorie (da JSON, non dal DB)
    json_path = os.path.join(app.root_path, "static", "data", "filtri_categoria.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    categorie = sorted(list(data.keys()))

    return render_template(
        "admin_notifiche.html",
        ttl_corrente=ttl_corrente,
        stats=stats,
        utenti=utenti,
        categorie=categorie,
        notifiche_admin=notifiche_admin
    )


@app.route("/admin/notifiche/pulisci")
@admin_required
def admin_pulisci_notifiche():
    """Elimina subito le notifiche lette e scadute"""
    pulisci_notifiche_vecchie()
    flash("Notifiche scadute eliminate con successo 🧹", "info")
    return redirect(url_for("admin_notifiche"))

@app.route("/admin/notifiche/invia", methods=["POST"])
@admin_required
def admin_invia_notifica():

    tipo_invio = request.form.getlist("tipo_invio")
    titolo = request.form.get("titolo", "").strip()
    messaggio = request.form.get("messaggio", "").strip()
    link = request.form.get("link", "").strip() or None

    if not titolo or not messaggio:
        flash("Titolo e messaggio sono obbligatori.", "error")
        return redirect(url_for("admin_notifiche"))

    # 1️⃣ FILTRA DESTINATARI
    destinatari = _filtra_utenti(request.form)

    if not destinatari:
        flash("Nessun destinatario trovato.", "error")
        return redirect(url_for("admin_notifiche"))

    # 2️⃣ SALVA STORICO ADMIN (PRIMA DELL’INVIO)
    try:
        # ✅ snapshot completo del form (liste incluse)
        filtro_snapshot = request.form.to_dict(flat=False)

        # ❌ rimuovi contenuto e campi non "filtro"
        for k in ("titolo", "messaggio", "link", "tipo_invio"):
            filtro_snapshot.pop(k, None)

        tab_attivo = request.form.get("tab-attivo") or "n/a"
        tipo_invio_str = ",".join(tipo_invio) if isinstance(tipo_invio, list) else str(tipo_invio)

        # ✅ destinatari solo se u-multipli
        destinatari_snapshot = None
        if tab_attivo == "u-multipli":
            destinatari_snapshot = []
            for u in destinatari:
                destinatari_snapshot.append({
                    "id": u["id"],
                    "username": u["username"] if "username" in u.keys() else None,
                    "email": u["email"] if "email" in u.keys() else None,
                    "nome": u["nome"] if "nome" in u.keys() else None,
                    "cognome": u["cognome"] if "cognome" in u.keys() else None,
                })

        conn = get_db_connection()
        c = get_cursor(conn)
        c.execute(sql("""
            INSERT INTO notifiche_admin (
                titolo,
                messaggio,
                link,
                tipo_invio,
                tab_attivo,
                filtro_json,
                destinatari_count,
                destinatari_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """), (
            titolo,
            messaggio,
            link,
            tipo_invio_str,
            tab_attivo,
            json.dumps(filtro_snapshot, ensure_ascii=False),
            len(destinatari),
            json.dumps(destinatari_snapshot, ensure_ascii=False) if destinatari_snapshot else None
        ))
        conn.commit()


    except Exception as e:
        print("❌ ERRORE storico notifiche_admin:", e)

    # 3️⃣ INVIO NOTIFICHE
    inviati = 0
    for user in destinatari:

        if "notifica" in tipo_invio or "entrambi" in tipo_invio:
            _crea_notifica(
                user["id"],
                titolo,
                messaggio,
                tipo="generica",
                link=link
            )
            emit_update_notifications(user["id"])

        if "email" in tipo_invio or "entrambi" in tipo_invio:
            _invia_email(
                destinazione=user["email"],
                oggetto=titolo,
                corpo=f"{messaggio}\n\n{link or ''}"
            )

        inviati += 1

    flash(f"Notifica inviata a {inviati} utenti.", "success")
    return redirect(url_for("admin_notifiche"))

import sqlite3

# Deve combaciare con l'ordine usato nel template INFO (loop.index 1..8)
CATEGORIE_INFO = [
    "Operatori benessere",             # 1
    "Aiuto in casa",                   # 2
    "Ripetizioni",                     # 3
    "Babysitter",                      # 4
    "Pet-sitter",                      # 5
    "Caregiver",                       # 6
    "escursioni-sport",                # 7
    "Biglietti spettacoli",            # 8
    "Libri scuola",                    # 9
    "Caffe & parole",                  # 10
]

def _norm(s: str) -> str:
    return (s or "").strip().lower()

def _parse_list_from_form(form, key: str):
    # accetta list dal form (checkbox multiple) oppure stringa singola
    vals = form.getlist(key)
    if vals:
        return [v.strip() for v in vals if v and v.strip()]
    v = (form.get(key) or "").strip()
    return [v] if v else []

def _parse_zone_terms(form):
    """
    Supporta:
      - input singolo "zona" (stringa)
      - oppure più input "zone" (checkbox / multiple)
    Inoltre, se l'admin incolla "Milano, Pavia" splitto per virgola.
    """
    zones = _parse_list_from_form(form, "zone")
    if not zones:
        raw = (form.get("zona") or "").strip()
        zones = [raw] if raw else []
    out = []
    for z in zones:
        for part in z.split(","):
            p = part.strip()
            if p:
                out.append(p)
    # dedup preservando ordine
    seen = set()
    dedup = []
    for z in out:
        k = z.lower()
        if k not in seen:
            seen.add(k)
            dedup.append(z)
    return dedup

def _categorie_to_info_indexes(categorie_selezionate):
    """
    Trasforma categorie (stringhe) in indici 1..8 per offro_i / cerco_i.
    """
    idx = []
    for cat in categorie_selezionate:
        c = _norm(cat)
        if c in CATEGORIE_INFO:
            idx.append(CATEGORIE_INFO.index(c) + 1)
    # dedup
    return sorted(set(idx))

def _is_checked(form, key: str) -> bool:
    """
    Gestisce checkbox Flask:
    - se spuntato arriva key in form con value spesso "on" o "1"
    - se non spuntato NON arriva proprio
    """
    v = form.get(key)
    return v is not None and str(v).strip().lower() not in ("0", "false", "off", "")


def _filtra_utenti(form):
    conn = get_db_connection()

    c = get_cursor(conn)

    # ------------------------------------------------------------
    # 0) Base filter per utenti
    # ------------------------------------------------------------
    BASE_UTENTI_WHERE = "u.sospeso = 0 AND u.attivo = 1"

    # ------------------------------------------------------------
    # 1) Tab attiva (decide quale modalità usare)
    # ------------------------------------------------------------
    tab = (form.get("tab-attivo") or "").strip()  # es: u-singolo, u-multipli, u-zona, u-categoria, u-avanzato, u-tutti

    # ------------------------------------------------------------
    # 2) Utente singolo
    # ------------------------------------------------------------
    if tab == "u-singolo":
        singolo = (form.get("utente_singolo") or "").strip()
        if singolo:
            valore = singolo.lower()
            c.execute(sql(f"""
                SELECT u.*
                FROM utenti u
                WHERE (LOWER(u.email) = ? OR LOWER(u.username) = ?)
                  AND {BASE_UTENTI_WHERE}
                LIMIT 1
            """), (valore, valore))
            row = c.fetchone()

            return [row] if row else []

        return []

    # ------------------------------------------------------------
    # 3) Selezione multipla
    # ------------------------------------------------------------
    if tab == "u-multipli":
        multipli = form.getlist("utenti_multipli")
        multipli = [m for m in multipli if str(m).strip().isdigit()]
        if not multipli:

            return []
        placeholders = ",".join(["?"] * len(multipli))
        c.execute(sql(f"""
            SELECT u.*
            FROM utenti u
            WHERE u.id IN ({placeholders})
              AND {BASE_UTENTI_WHERE}
        """), multipli)
        rows = c.fetchall()

        return rows

    # ------------------------------------------------------------
    # 4) Tutti
    # ------------------------------------------------------------
    if tab == "u-tutti":
        c.execute(sql(f"""
            SELECT u.*
            FROM utenti u
            WHERE {BASE_UTENTI_WHERE}
            ORDER BY u.nome, u.cognome
        """))
        rows = c.fetchall()

        return rows

    # ------------------------------------------------------------
    # 5) FILTRO AVANZATO (ZONA / CATEGORIA / INCROCIO)
    #    Lo usiamo sia per u-zona, u-categoria, sia per un futuro u-avanzato.
    # ------------------------------------------------------------

    # ---- input
    zone_terms = _parse_zone_terms(form)                  # lista stringhe
    # 🔹 normalizzazione zona: prefisso principale (NO JSON)
    zone_prefixes = []

    for z in zone_terms:
        z = _norm(z)
        if not z:
            continue

        # prendo solo la parte prima di separatori
        for sep in ["–", "-", ","]:
            if sep in z:
                z = z.split(sep)[0].strip()
                break

        if z and z not in zone_prefixes:
            zone_prefixes.append(z)

    categorie_sel = _parse_list_from_form(form, "categorie")  # lista stringhe (es: "babysitter", "operatori benessere")
    categorie_sel_norm = [_norm(x) for x in categorie_sel if _norm(x)]

    # ---- toggle (checkbox) – la UI li manderà così allo step 2
    # per ora, metto default "sensati" in base alla tab:
    include_zona_info    = _is_checked(form, "zona_info")
    include_zona_annunci = _is_checked(form, "zona_annunci")

    include_cat_cerco    = _is_checked(form, "cat_cerco_info")
    include_cat_offro    = _is_checked(form, "cat_offro_info")
    include_cat_annunci  = _is_checked(form, "cat_annunci")

    # Default automatici se la UI non li manda ancora:
    if tab == "u-zona":
        if ("zona_info" not in form) and ("zona_annunci" not in form):
            include_zona_info = True
            include_zona_annunci = True

    if tab == "u-categoria":
        if not (include_cat_cerco or include_cat_offro or include_cat_annunci):
            include_cat_cerco = True
            include_cat_offro = True
            include_cat_annunci = True

    # Se in futuro avrai tab "u-avanzato", lì non setto default: lo decidi dalla UI.
    # Qui però evitiamo "nessun filtro" per errore.
    has_zona = len(zone_prefixes) > 0
    has_cat  = len(categorie_sel_norm) > 0

    # Se tab è zona/categoria ma input vuoto => nessun destinatario
    if (tab in ["u-zona", "u-categoria"] or tab == "u-avanzato"):
        if not has_zona and not has_cat:

            return []

    # ------------------------------------------------------------
    # 5A) Subquery: utenti per ZONA
    # ------------------------------------------------------------
    zona_info_sql = None
    zona_info_params = []

    zona_annunci_sql = None
    zona_annunci_params = []

    if has_zona:

        # ---------------- INFO ----------------
        if include_zona_info and zone_prefixes:
            conds = " OR ".join(
                ["LOWER(u.citta) LIKE ?"] * len(zone_prefixes)
            )
            zona_info_sql = f"""
                SELECT u.id AS uid
                FROM utenti u
                WHERE {BASE_UTENTI_WHERE}
                  AND ({conds})
            """
            zona_info_params = [f"{z}%" for z in zone_prefixes]

        # ---------------- ANNUNCI ----------------
        if include_zona_annunci and zone_prefixes:
            conds = " OR ".join(
                ["LOWER(a.zona) LIKE ?"] * len(zone_prefixes)
            )
            zona_annunci_sql = f"""
                SELECT a.utente_id AS uid
                FROM annunci a
                JOIN utenti u ON u.id = a.utente_id
                WHERE {BASE_UTENTI_WHERE}
                  AND ({conds})
            """
            zona_annunci_params = [f"{z}%" for z in zone_prefixes]

    # 🔒 BLOCCO DURO: zona richiesta ma nessun match reale
    zona_sql = None
    zona_params = []

    if has_zona:

        if include_zona_info and not include_zona_annunci:
            # SOLO INFO
            if not zona_info_sql:

                return []
            zona_sql = zona_info_sql
            zona_params = zona_info_params

        elif include_zona_annunci and not include_zona_info:
            # SOLO ANNUNCI
            if not zona_annunci_sql:

                return []
            zona_sql = zona_annunci_sql
            zona_params = zona_annunci_params

        elif include_zona_info and include_zona_annunci:
            # INFO + ANNUNCI
            if not zona_info_sql and not zona_annunci_sql:

                return []

            queries = []
            if zona_info_sql:
                queries.append(zona_info_sql)
            if zona_annunci_sql:
                queries.append(zona_annunci_sql)

            zona_sql = " UNION ".join(queries)
            zona_params = zona_info_params + zona_annunci_params

        else:
            # zona richiesta ma nessun checkbox valido

            return []

        # BLOCCO DURO FINALE
        count = conn.execute(
            f"SELECT COUNT(*) FROM ({zona_sql})",
            zona_params
        ).fetchone()[0]

        if count == 0:

            return []

    # ------------------------------------------------------------
    # 5B) Subquery: utenti per CATEGORIA
    # ------------------------------------------------------------
    cat_subqueries = []
    cat_params = []

    if has_cat:
        # ---- categoria da ANNUNCI (annunci.categoria)
        if include_cat_annunci:
            placeholders = ",".join(["?"] * len(categorie_sel_norm))
            cat_subqueries.append(f"""
                SELECT a.utente_id AS uid
                FROM annunci a
                JOIN utenti u ON u.id = a.utente_id
                WHERE {BASE_UTENTI_WHERE}
                  AND LOWER(a.categoria) IN ({placeholders})
            """)
            cat_params.extend(categorie_sel_norm)

        # ---- categoria da INFO (offro_i / cerco_i)
        idx = _categorie_to_info_indexes(categorie_sel_norm)

        # costruiamo condizioni OR tipo: (u.cerco_1=1 OR u.cerco_3=1 ...)
        if idx and include_cat_cerco:
            conds = " OR ".join([f"COALESCE(u.cerco_{i},0)=1" for i in idx])
            cat_subqueries.append(f"""
                SELECT u.id AS uid
                FROM utenti u
                WHERE {BASE_UTENTI_WHERE}
                  AND ({conds})
            """)

        if idx and include_cat_offro:
            conds = " OR ".join([f"COALESCE(u.offro_{i},0)=1" for i in idx])
            cat_subqueries.append(f"""
                SELECT u.id AS uid
                FROM utenti u
                WHERE {BASE_UTENTI_WHERE}
                  AND ({conds})
            """)

    cat_sql = None
    if cat_subqueries:
        cat_sql = " UNION ".join(cat_subqueries)

    # ------------------------------------------------------------
    # 5C) Combinazione: solo zona / solo categoria / incrocio (AND)
    # ------------------------------------------------------------
    final_ids_sql = None
    final_params = []

    if has_zona and has_cat:
        if not zona_sql or not cat_sql:

            return []
        final_ids_sql = f"""
            SELECT uid FROM (
                {zona_sql}
                INTERSECT
                {cat_sql}
            )
        """
        final_params = zona_params + cat_params

    elif has_zona:
        if not zona_sql:

            return []
        final_ids_sql = f"""
            SELECT uid FROM (
                {zona_sql}
            )
        """
        final_params = zona_params

    elif has_cat:
        if not cat_sql:

            return []
        final_ids_sql = f"""
            SELECT uid FROM (
                {cat_sql}
            )
        """
        final_params = cat_params

    else:

        return []
    # ------------------------------------------------------------
    # 5D) Query finale utenti
    # ------------------------------------------------------------
    c.execute(sql(f"""
        WITH destinatari AS (
            {final_ids_sql}
        )
        SELECT u.*
        FROM utenti u
        JOIN destinatari d ON d.uid = u.id
        WHERE {BASE_UTENTI_WHERE}
        ORDER BY u.nome, u.cognome
    """), final_params)

    rows = c.fetchall()

    return rows


def _crea_notifica(id_utente, titolo, messaggio, tipo="generica", link=None):
    conn = get_db_connection()
    try:
        c = get_cursor(conn)

        c.execute(sql("""
            INSERT INTO notifiche (
                id_utente,
                titolo,
                messaggio,
                tipo,
                link,
                letta
            ) VALUES (?, ?, ?, ?, ?, 0)
        """), (id_utente, titolo, messaggio, tipo, link))

        conn.commit()

    finally:
        try:
            conn.close()
        except:
            pass

def processa_match_nuovi_annunci():
    import sqlite3
    from datetime import datetime
    from zoneinfo import ZoneInfo

    conn = sqlite3.connect("database.db", timeout=30)

    c = get_cursor(conn)

    nuovi = c.execute(sql("""
        SELECT id, utente_id, categoria, zona
        FROM annunci
        WHERE stato = 'approvato'
          AND match_da_processare = 1
    """)).fetchall()

    if not nuovi:

        return 0

    annunci_processati = []
    notifiche_per_utente = {}

    for a in nuovi:
        annuncio_id = a["id"]
        offre_id = a["utente_id"]
        categoria = (a["categoria"] or "").strip()
        zona = (a["zona"] or "").strip()

        idx = CATEGORIA_TO_INDEX.get(to_slug(categoria))
        if not idx:
            annunci_processati.append(annuncio_id)
            continue

        utenti = c.execute(sql(f"""
            SELECT id, citta
            FROM utenti
            WHERE cerco_{idx} = 1
              AND attivo = 1
              AND sospeso = 0
              AND visibile_pubblicamente = 1
              AND id != ?
        """), (offre_id,)).fetchall()

        for u in utenti:
            if not place_match(zona, u["citta"] or ""):
                continue

            try:
                c.execute(sql("""
                    INSERT INTO match_utenti
                    (utente_cerca_id, utente_offre_id, categoria, zona, annuncio_id)
                    VALUES (?, ?, ?, ?, ?)
                """), (u["id"], offre_id, categoria, zona, annuncio_id))

                notifiche_per_utente.setdefault(u["id"], {})
                notifiche_per_utente[u["id"]].setdefault(categoria, 0)
                notifiche_per_utente[u["id"]][categoria] += 1

            except sqlite3.IntegrityError:
                pass

        annunci_processati.append(annuncio_id)

    # 🔔 NOTIFICHE RIASSUNTIVE (1 PER UTENTE)
    now = datetime.now(ZoneInfo("Europe/Rome"))

    for user_id, cats in notifiche_per_utente.items():

        righe = []
        for categoria, n in cats.items():
            label = "annuncio" if n == 1 else "annunci"
            righe.append(f"• {categoria} ({n})")

        messaggio = (
            "Nuovi annunci nella tua zona:\n"
            + "\n".join(righe)
        )

        c.execute(sql("""
            INSERT INTO notifiche (
                id_utente, titolo, messaggio, link, tipo, data
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """), (
            user_id,
            "Nuovi annunci disponibili",
            messaggio,
            "/cerca",
            "match",
            now
        ))

    # Segna match come notificati
    c.execute(sql("UPDATE match_utenti SET notificato = 1 WHERE notificato = 0"))

    if annunci_processati:
        q = ",".join("?" * len(annunci_processati))
        c.execute(
            f"UPDATE annunci SET match_da_processare = 0 WHERE id IN ({q})",
            annunci_processati
        )

    conn.commit()

    return len(annunci_processati)


def _invia_email(destinazione, oggetto, corpo=None, html_template=None, **kwargs):
    """
    Funzione centralizzata invio email.

    Parametri:
    - destinazione: email destinatario
    - oggetto: subject
    - corpo: testo semplice fallback
    - html_template: path template Jinja (opzionale)
    - kwargs: variabili per template
    """

    try:
        msg = Message(
            subject=oggetto,
            recipients=[destinazione]
        )

        # ✅ Se è specificato un template HTML
        if html_template:
            msg.html = render_template(html_template, **kwargs)

            # fallback testo
            msg.body = corpo or "Apri questa email in formato HTML."

        else:
            msg.body = corpo or ""

        mail.send(msg)

    except Exception as e:
        print("Errore invio email:", e)

def _normalizza_lista(value):
    if not value:
        return []
    if isinstance(value, list):
        return [v for v in value if v.strip()]
    return [value] if value.strip() else []

# ==========================================================
# NOTIFICHE SERVIZIO URGENTE
# ==========================================================
import sqlite3

def notifica_urgente(annuncio_id, attivazione_id=None, eseguito_da="admin"):
    """
    Invia notifiche per un annuncio urgente.
    Viene chiamata:
    - da admin (toggle)
    - da acquisto servizio urgente
    - da riattivazione futura
    """

    conn = get_db_connection()
    c = get_cursor(conn)

    # ---------------------------------------------------------
    # 1️⃣ Recupera annuncio + verifica servizio urgente ATTIVO
    # ---------------------------------------------------------
    c.execute(sql(f"""
        SELECT
            a.id,
            a.utente_id,
            a.categoria,
            a.tipo_annuncio,
            a.provincia,
            a.zona,
            a.titolo,
            u.username
        FROM annunci a
        JOIN utenti u ON u.id = a.utente_id
        JOIN attivazioni_servizi act ON act.annuncio_id = a.id
        JOIN servizi s ON s.id = act.servizio_id
        WHERE a.id = ?
          AND a.stato = 'approvato'
          AND s.codice = 'annuncio_urgente'
          AND act.stato = 'attivo'
          AND act.data_inizio <= {now_sql()}
          AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
    """), (annuncio_id,))
    annuncio = c.fetchone()

    if not annuncio:

        print("⚠️ Annuncio non valido o non urgente.")
        return

    (
        annuncio_id,
        autore_id,
        categoria,
        tipo_annuncio,
        provincia,
        zona,
        titolo,
        username
    ) = annuncio

    tipo_opposto = "cerco" if tipo_annuncio == "offro" else "offro"
    luogo = zona or provincia

    notificati = set()

    # ---------------------------------------------------------
    # 2️⃣ PRIORITÀ 1 — ANNUNCI COMPATIBILI
    # ---------------------------------------------------------
    c.execute(sql("""
        SELECT DISTINCT a.utente_id
        FROM annunci a
        JOIN utenti u ON u.id = a.utente_id
        WHERE a.stato = 'approvato'
          AND a.tipo_annuncio = ?
          AND a.categoria = ?
          AND a.provincia = ?
          AND a.utente_id != ?
          AND u.sospeso = 0
          AND u.disattivato_admin = 0
          AND u.attivo = 1
          AND u.email_notifiche = 1
    """), (tipo_opposto, categoria, provincia, autore_id))

    for (uid,) in c.fetchall():
        notificati.add(uid)

    # ---------------------------------------------------------
    # 3️⃣ PRIORITÀ 2 — INFO UTENTE (match per CATEGORIA specifica)
    # ---------------------------------------------------------
    categoria_slug = to_slug(categoria)
    categoria_index = CATEGORIA_TO_INDEX.get(categoria_slug)

    if categoria_index:
        colonna = f"{tipo_opposto}_{categoria_index}"

        c.execute(sql(f"""
            SELECT id
            FROM utenti
            WHERE provincia = ?
              AND id != ?
              AND sospeso = 0
              AND (disattivato_admin IS NULL OR disattivato_admin = 0)
              AND attivo = 1
              AND email_notifiche = 1
              AND {colonna} = 1
        """), (provincia, autore_id))

        for (uid,) in c.fetchall():
            notificati.add(uid)

    if not notificati:

        print("ℹ️ Nessun destinatario compatibile.")
        return

    # ---------------------------------------------------------
    # 4️⃣ Inserimento notifiche (TESTO DEFINITIVO VISIBILE)
    # ---------------------------------------------------------

    messaggio = (
        "Annuncio urgente in zona\n"
        f"{categoria}|{tipo_annuncio}|{luogo}|{username}"
    )

    for uid in notificati:
        c.execute(sql("""
            INSERT INTO notifiche (
                id_utente,
                titolo,
                messaggio,
                link,
                tipo
            ) VALUES (?, ?, ?, ?, ?)
        """), (
            uid,
            "urgente",  # titolo tecnico, non visibile
            messaggio,
            f"/annuncio/{annuncio_id}",
            "urgente"
        ))

    # ---------------------------------------------------------
    # 5️⃣ Storico servizio (audit)
    # ---------------------------------------------------------
    if attivazione_id:
        c.execute(sql("""
            INSERT INTO storico_servizi (
                attivazione_id,
                azione,
                eseguito_da,
                note
            ) VALUES (?, 'notifica_inviata', ?, ?)
        """), (
            attivazione_id,
            eseguito_da,
            f"Inviate {len(notificati)} notifiche urgenti"
        ))

    conn.commit()


    print(f"✅ Notifica urgente inviata a {len(notificati)} utenti.")

    # ---------------------------------------------------------
    # 6️⃣ EMISSIONE SOCKET REALTIME (come recensioni)
    # ---------------------------------------------------------
    for uid in notificati:
        count = conta_non_lette(uid)
        emit_update_notifications(uid)

# ==========================================================
# APPROVA / RIFIUTA RECENSIONI E RISPOSTE
# ==========================================================
@app.route("/admin/recensioni/approva/<int:id>")
@admin_required
def approva_recensione(id):
    from models import approva_elemento
    try:
        approva_elemento("recensioni", id)

        conn = get_db_connection()
        c = get_cursor(conn)
        c.execute(sql("""
            SELECT r.id_autore, r.id_destinatario, r.ultima_modifica, u.username
            FROM recensioni r
            JOIN utenti u ON r.id_autore = u.id
            WHERE r.id = ?
        """), (id,))
        row = c.fetchone()


        if row:
            id_autore = list(row.values())[0]
            id_destinatario = list(row.values())[1]
            ultima_modifica = list(row.values())[2]
            username_autore = list(row.values())[3] or "utente"

            if ultima_modifica:
                messaggio = f"@{username_autore} ha modificato la sua recensione su di te"
            else:
                messaggio = f"Hai ricevuto una nuova recensione da @{username_autore}"

            crea_notifica(
                id_destinatario,
                messaggio,
                link=url_for("mie_recensioni_ricevute")
            )

            emit_update_notifications(id_destinatario)

        # 🔁 Aggiorna counters admin (recensioni in attesa)
        invalidate_admin_counters()

        flash("✅ Recensione approvata e notifica inviata!", "success")

    except Exception as e:
        flash(f"Errore durante l'approvazione: {e}", "danger")

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/admin/recensioni"):
        return redirect(next_url)

    return redirect(url_for("admin_recensioni"))


@app.route("/admin/recensioni/rifiuta/<int:id>")
@admin_required
def rifiuta_recensione(id):
    from models import rifiuta_elemento
    try:
        rifiuta_elemento("recensioni", id)

        conn = get_db_connection()
        c = get_cursor(conn)
        c.execute(sql("SELECT id_autore FROM recensioni WHERE id = ?"), (id,))
        row = c.fetchone()


        if row:
            id_autore = list(row.values())[0]

            crea_notifica(
                id_autore,
                "La tua recensione è stata rifiutata per contenuto poco appropriato. Modificala e inviala di nuovo. ❌",
                link=url_for("mie_recensioni")
            )

            emit_update_notifications(id_autore)

        # 🔁 Aggiorna counters admin (recensioni in attesa)
        invalidate_admin_counters()

        flash("❌ Recensione rifiutata!", "warning")

    except Exception as e:
        flash(f"Errore durante il rifiuto: {e}", "danger")

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/admin/recensioni"):
        return redirect(next_url)

    return redirect(url_for("admin_recensioni"))

@app.route("/admin/risposte/approva/<int:id>")
@admin_required
def approva_risposta(id):
    from models import approva_elemento
    try:
        approva_elemento("risposte_recensioni", id)

        conn = get_db_connection()
        c = get_cursor(conn)
        c.execute(sql("""
            SELECT r.id_autore, u.username
            FROM recensioni r
            JOIN risposte_recensioni rr ON rr.id_recensione = r.id
            JOIN utenti u ON rr.id_autore = u.id
            WHERE rr.id = ?
        """), (id,))
        row = c.fetchone()


        if row:
            id_autore = list(row.values())[0]
            username_risposta = list(row.values())[1] or "utente"

            crea_notifica(
                id_autore,
                f"La tua recensione a @{username_risposta} ha ricevuto una risposta 💬",
                link=url_for("mie_recensioni")
            )

            emit_update_notifications(id_autore)

        # 🔁 Aggiorna counters admin (recensioni in attesa)
        invalidate_admin_counters()

        flash("✅ Risposta approvata e notifica inviata!", "success")

    except Exception as e:
        flash(f"Errore durante l'approvazione della risposta: {e}", "danger")

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/admin/recensioni"):
        return redirect(next_url)

    return redirect(url_for("admin_recensioni"))

@app.route("/admin/risposte/rifiuta/<int:id>")
@admin_required
def rifiuta_risposta(id):
    from models import rifiuta_elemento
    try:
        # 1️⃣ Imposto lo stato della risposta a "rifiutata"
        rifiuta_elemento("risposte_recensioni", id)

        # 2️⃣ Recupero l'autore della risposta
        conn = get_db_connection()
        c = get_cursor(conn)
        c.execute(sql("SELECT id_autore FROM risposte_recensioni WHERE id = ?"), (id,))
        row = c.fetchone()


        if row:
            id_autore = list(row.values())[0]

            # 3️⃣ Creo la notifica per l'autore della risposta
            crea_notifica(
                id_autore,
                "La tua risposta a una recensione è stata rifiutata per contenuto poco appropriato. Modificala e inviala di nuovo. ❌",
                link=url_for("mie_recensioni_ricevute")  # 👉 o la route dove vede le sue risposte
            )

            # 4️⃣ Aggiorno in tempo reale il badge notifiche (Socket.IO)
            emit_update_notifications(id_autore)

        # 🔁 Aggiorna counters admin (recensioni in attesa)
        invalidate_admin_counters()

        flash("❌ Risposta rifiutata!", "warning")

    except Exception as e:
        flash(f"Errore durante il rifiuto della risposta: {e}", "danger")

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/admin/recensioni"):
        return redirect(next_url)

    return redirect(url_for("admin_recensioni"))

# ==========================================================
# ADMIN – LISTA ANNUNCI
# ==========================================================
@app.route("/admin/annunci")
@admin_required
def admin_annunci():

    # =========================
    # FILTRI
    # =========================
    utente = (request.args.get("utente") or "").strip().lower()
    categoria = (request.args.get("categoria") or "").strip()
    zona = (request.args.get("zona") or "").strip()
    provincia = (request.args.get("provincia") or "").strip()
    stato = (request.args.get("stato") or "").strip().lower()

    # 🔁 NUOVO: offro / cerco
    tipo_annuncio = (request.args.get("tipo_annuncio") or "").strip().lower()
    if tipo_annuncio not in ("offro", "cerco"):
        tipo_annuncio = ""

    # =========================
    # DB
    # =========================
    conn = get_db_connection()

    c = get_cursor(conn)

    query = f"""
        SELECT
            a.id,
            a.titolo,
            a.categoria,
            a.tipo_annuncio,
            a.zona,
            a.provincia,
            a.stato,
            a.utente_id,
            u.nome,
            u.cognome,
            u.email,

            /* BOOST LISTA */
            CASE WHEN EXISTS (
                SELECT 1
                FROM attivazioni_servizi act
                JOIN servizi s ON s.id = act.servizio_id
                WHERE act.annuncio_id = a.id
                  AND s.codice = 'boost_lista'
                  AND act.stato = 'attivo'
                  AND act.data_inizio <= {now_sql()}
                  AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
            ) THEN 1 ELSE 0 END AS has_boost_lista,

            /* VETRINA */
            CASE WHEN EXISTS (
                SELECT 1
                FROM attivazioni_servizi act
                JOIN servizi s ON s.id = act.servizio_id
                WHERE act.annuncio_id = a.id
                  AND s.codice = 'vetrina_annuncio'
                  AND act.stato = 'attivo'
                  AND act.data_inizio <= {now_sql()}
                  AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
            ) THEN 1 ELSE 0 END AS has_vetrina,

            /* BADGE EVIDENZA */
            CASE WHEN EXISTS (
                SELECT 1
                FROM attivazioni_servizi act
                JOIN servizi s ON s.id = act.servizio_id
                WHERE act.annuncio_id = a.id
                  AND s.codice = 'badge_evidenza'
                  AND act.stato = 'attivo'
                  AND act.data_inizio <= {now_sql()}
                  AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
            ) THEN 1 ELSE 0 END AS has_badge_evidenza,

            /* ANNUNCIO URGENTE */
            CASE WHEN EXISTS (
                SELECT 1
                FROM attivazioni_servizi act
                JOIN servizi s ON s.id = act.servizio_id
                WHERE act.annuncio_id = a.id
                  AND s.codice = 'annuncio_urgente'
                  AND act.stato = 'attivo'
                  AND act.data_inizio <= {now_sql()}
                  AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
            ) THEN 1 ELSE 0 END AS has_urgente,

            /* BADGE AFFIDABILITÀ */
            CASE WHEN EXISTS (
                SELECT 1
                FROM attivazioni_servizi act
                JOIN servizi s ON s.id = act.servizio_id
                WHERE act.utente_id = a.utente_id
                  AND act.annuncio_id IS NULL
                  AND s.codice = 'badge_affidabilita'
                  AND act.stato = 'attivo'
            ) THEN 1 ELSE 0 END AS has_affidabilita

        FROM annunci a
        JOIN utenti u ON a.utente_id = u.id
        WHERE 1=1
    """
    params = []

    # =========================
    # APPLICAZIONE FILTRI
    # =========================
    if utente:
        like = f"%{utente}%"
        query += " AND (LOWER(u.nome) LIKE ? OR LOWER(u.cognome) LIKE ?)"
        params.extend([like, like])

    if categoria:
        query += " AND a.categoria = ?"
        params.append(categoria)

    if tipo_annuncio:
        query += " AND a.tipo_annuncio = ?"
        params.append(tipo_annuncio)

    if provincia:
        query += " AND LOWER(a.provincia) = LOWER(?)"
        params.append(provincia)

    if zona:
        query += " AND LOWER(a.zona) LIKE ?"
        params.append(f"%{zona.lower()}%")

    if stato:
        query += " AND a.stato = ?"
        params.append(stato)

    query += " ORDER BY a.data_pubblicazione DESC"

    # =========================
    # EXEC
    # =========================
    c.execute(sql(query), params)
    annunci = [dict(row) for row in c.fetchall()]

    # =========================
    # CATEGORIE (select admin)
    # =========================
    with open("static/data/filtri_categoria.json", encoding="utf-8") as f:
        categorie = list(json.load(f).keys())

    return render_template(
        "admin_annunci.html",
        annunci=annunci,
        categorie=categorie
    )

@app.route("/admin/annunci/approva/<int:id>")
@admin_required
def approva_annuncio(id):
    conn = get_db_connection()

    c = get_cursor(conn)

    c.execute(sql(f"""
        UPDATE annunci
        SET stato = 'approvato',
            approvato_il = {now_sql()},
            match_da_processare = 1
        WHERE id = ?
    """), (id,))

    c.execute(sql("SELECT utente_id FROM annunci WHERE id = ?"), (id,))
    row = c.fetchone()

    utente_id = None
    if row:
        utente_id = row["utente_id"]
        c.execute(sql("UPDATE utenti SET visibile_pubblicamente = 1 WHERE id = ?"), (utente_id,))
        conn.commit()



    if utente_id:
        crea_notifica(
            utente_id,
            "Il tuo annuncio è stato approvato ed è ora visibile su MyLocalCare ✅",
            link=url_for("dashboard") + "?tab=annunci"
        )

        emit_update_notifications(utente_id)

    # 🔁 Aggiorna counters admin (annunci in attesa)
    invalidate_admin_counters()

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/admin/annunci"):
        return redirect(next_url)
    return redirect(url_for("admin_annunci"))

@app.route("/admin/annunci/rifiuta/<int:id>")
@admin_required
def rifiuta_annuncio(id):
    conn = get_db_connection()
    c = get_cursor(conn)

    # 1️⃣ Update stato
    c.execute(sql("""
        UPDATE annunci
        SET stato = 'rifiutato'
        WHERE id = ?
    """), (id,))

    # 2️⃣ Recupero utente DOPO update (come approva)
    c.execute(sql("SELECT utente_id FROM annunci WHERE id = ?"), (id,))
    row = c.fetchone()

    utente_id = None
    if row:
        utente_id = row["utente_id"]
        conn.commit()

    # 3️⃣ Notifica dopo commit completo
    if utente_id:
        crea_notifica(
            utente_id,
            "Il tuo annuncio è stato rifiutato perché non conforme alle linee guida di MyLocalCare. "
            "Puoi modificarlo e ripubblicarlo. ❌",
            link=url_for("dashboard") + "?tab=annunci"
        )

        emit_update_notifications(utente_id)

    invalidate_admin_counters()

    flash("Annuncio rifiutato ❌", "warning")

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/admin/annunci"):
        return redirect(next_url)

    return redirect(url_for("admin_annunci"))

# ==========================================================
# NOTIFICHE - FUNZIONI DI SUPPORTO (AGGIUNTA)
# ==========================================================
def get_notifiche_utente(user_id):
    conn = get_db_connection()
    notifiche = conn.execute(
        "SELECT * FROM notifiche WHERE id_utente = ? ORDER BY data DESC",
        (user_id,)
    ).fetchall()

    return notifiche

def conta_non_lette(user_id):
    conn = get_db_connection()
    c = get_cursor(conn)
    c.execute(sql("SELECT COUNT(*) FROM notifiche WHERE id_utente = ? AND letta = 0"), (user_id,))
    count = fetchone_value(c.fetchone())

    return count

def segna_notifica_letta(notifica_id, user_id):
    conn = get_db_connection()
    conn.execute(sql(f"""
        UPDATE notifiche
        SET data_lettura = {now_sql()}
        WHERE id = ? AND id_utente = ?
    """), (notifica_id, user_id))
    conn.commit()

@app.route("/notifiche/segna_tutte_lette", methods=["POST"])
def segna_tutte_lette_route():
    if "utente_id" not in session:
        return jsonify({"success": False}), 403

    from models import segna_tutte_lette
    segna_tutte_lette(session["utente_id"])

    # 🔔 Aggiorna il badge in tempo reale
    emit_update_notifications(session["utente_id"])

    return jsonify({"success": True})

@app.route("/notifiche/elimina_tutte", methods=["POST"])
def elimina_tutte_notifiche_route():
    if "utente_id" not in session:
        return jsonify({"success": False}), 403

    from models import elimina_tutte_notifiche
    elimina_tutte_notifiche(session["utente_id"])

    # 🔔 Aggiorna il badge in tempo reale
    emit_update_notifications(session["utente_id"])

    return jsonify({"success": True})

def pulisci_notifiche_vecchie():
    """Elimina notifiche lette e scadute in base al TTL configurato"""
    giorni = app.config.get("NOTIFICHE_TTL_GIORNI", 10)
    conn = get_db_connection()
    conn.execute(sql(f"""
        DELETE FROM notifiche
        WHERE letta = 1
          AND data_lettura < {now_sql()} - INTERVAL '{giorni} days'
    """))
    conn.commit()


# Rende disponibile in tutti i template un helper per le notifiche non lette
@app.context_processor
def utility_functions():
    def unread_chat():
        """Conta solo i messaggi chat non letti"""
        if g.utente:
            return count_chat_non_letti(g.utente['id'])
        return 0

    def unread_notifications():
        """Conta solo le notifiche non lette"""
        if g.utente:
            return conta_non_lette(g.utente['id'])
        return 0

    # (Mantieni unread_count solo se serve un totale combinato)
    def unread_count():
        """Totale generale (chat + notifiche), se serve in futuro"""
        if g.utente:
            return unread_chat() + unread_notifications()
        return 0

    return dict(
        unread_chat=unread_chat,
        unread_notifications=unread_notifications,
        unread_count=unread_count
    )

@app.context_processor
def inject_helpers():
    from models import get_risposta_by_recensione
    return dict(get_risposta_by_recensione=get_risposta_by_recensione)

@app.context_processor
def inject_pytz():
    import pytz
    return dict(pytz=pytz)

@app.route('/notifiche/unread_count')
@login_required
def notifiche_unread_count():
    return jsonify({"count": conta_non_lette(g.utente['id'])})

# ==========================================================
# 🔹 CACHE per ADMIN COUNTERS
# ==========================================================
from time import time

# Inizializza cache e TTL (5 secondi di durata)
app.config.setdefault("_ADMIN_COUNTERS_CACHE", {"ts": 0, "payload": None})
app.config.setdefault("_ADMIN_COUNTERS_TTL", 1)  # secondi

# ==========================================================
# 🧹 Helper: resetta cache admin e aggiorna il badge live
# ==========================================================
def invalidate_admin_counters():
    """Pulisce la cache counters e forza aggiornamento admin live."""
    try:
        app.config["_ADMIN_COUNTERS_CACHE"] = {"ts": 0, "payload": None}
        socketio.emit("update_admin_counters", namespace="/")
        print("♻️ Cache admin counters invalidata e badge aggiornato.")
    except Exception as e:
        print(f"⚠️ Errore invalidate_admin_counters: {e}")


# ==========================================================
# 3️⃣ MIDDLEWARE E DASHBOARD UTENTE
# ==========================================================

# --- Middleware per proteggere pagine riservate ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('utente_id')
    if user_id is None:
        g.utente = None
    else:
        conn = get_db_connection()
        cur = get_cursor(conn)
        cur.execute(sql('SELECT * FROM utenti WHERE id = ?'), (user_id,))
        g.utente = cur.fetchone()

    # 🔹 Identifica il percorso corrente (utile per la navbar)
    g.path = request.path

# --- Dashboard Utente ---
@app.route("/annuncio/<int:id>/modifica", methods=["GET", "POST"])
@login_required
def modifica_annuncio(id):
    conn = get_db_connection()

    c = get_cursor(conn)

    annuncio = c.execute(
        "SELECT * FROM annunci WHERE id = ?",
        (id,)
    ).fetchone()

    # 🔒 Sicurezza: annuncio esistente e di proprietà dell’utente
    if not annuncio or annuncio["utente_id"] != g.utente["id"]:

        flash("Non puoi modificare questo annuncio.", "error")
        return redirect(url_for("dashboard"))

    # =========================================================
    # 📤 POST
    # =========================================================
    if request.method == "POST":

        # 🧩 Protezione extra contro manomissione ID
        id_form = request.form.get("id_annuncio")
        if id_form and str(id_form) != str(id):

            flash("Tentativo di modifica non autorizzato.", "error")
            return redirect(url_for("dashboard"))

        # 🔹 CAMPI BASE
        titolo = request.form.get("titolo", "").strip()
        descrizione = request.form.get("descrizione", "").strip()
        raw_categoria = request.form.get("categoria", "").strip()
        categoria = to_slug(raw_categoria)
        tipo_annuncio = request.form.get("tipo_annuncio", "").strip().lower()

        # 🔹 ZONA + PROVINCIA
        zona = request.form.get("zona", "").strip()
        provincia = request.form.get("provincia", "").strip()

        # 🔹 ALTRI CAMPI
        prezzo = request.form.get("prezzo", "").strip()
        telefono = request.form.get("telefono", "").strip()
        email = request.form.get("email", "").strip()
        bio = request.form.get("bio_utente", "").strip()
        filtri = request.form.getlist("filtri_categoria")

        # =====================================================
        # 🛡️ VALIDAZIONI
        # =====================================================
        if tipo_annuncio not in ("offro", "cerco"):

            flash("Devi specificare se l’annuncio è 'Offro' oppure 'Cerco'.", "warning")
            return redirect(url_for("modifica_annuncio", id=id))

        if not zona or not provincia:

            flash("Seleziona un comune valido dall’elenco.", "warning")
            return redirect(url_for("modifica_annuncio", id=id))

        # =====================================================
        # 📸 MEDIA – gestione immagini
        # =====================================================
        immagini_rimanenti = request.form.getlist("immagini_rimanenti")
        immagini_da_cancellare = request.form.getlist("cancellate")

        # 🗑️ Elimina immagini rimosse
        for foto in immagini_da_cancellare:
            percorso_file = os.path.join("static", foto)
            if os.path.exists(percorso_file):
                try:
                    os.remove(percorso_file)
                except Exception as e:
                    print(f"⚠️ Impossibile eliminare {percorso_file}: {e}")

        # 📸 Upload nuove immagini
        nuove_foto = request.files.getlist("foto") or request.files.getlist("media")
        upload_dir = os.path.join("static", "uploads", "annunci")
        os.makedirs(upload_dir, exist_ok=True)

        for foto in nuove_foto:
            if foto and foto.filename:
                nome_file = f"{uuid.uuid4().hex}_{foto.filename}"
                percorso = os.path.join(upload_dir, nome_file)
                foto.save(percorso)
                immagini_rimanenti.append(f"uploads/annunci/{nome_file}")

        media_finale = ",".join(immagini_rimanenti)

        # =====================================================
        # 💾 UPDATE DB
        # =====================================================
        c.execute(sql("""
            UPDATE annunci
            SET
                titolo = ?,
                descrizione = ?,
                categoria = ?,
                tipo_annuncio = ?,
                zona = ?,
                provincia = ?,
                prezzo = ?,
                telefono = ?,
                email = ?,
                bio_utente = ?,
                media = ?,
                filtri_categoria = ?,
                stato = 'in_attesa'
            WHERE id = ?
        """), (
            titolo,
            descrizione,
            categoria,
            tipo_annuncio,
            zona,
            provincia,
            prezzo,
            telefono,
            email,
            bio,
            media_finale,
            ",".join(filtri),
            id
        ))

        conn.commit()


        # 🔁 Aggiorna contatori admin
        invalidate_admin_counters()

        flash("✅ Annuncio aggiornato con successo (sarà revisionato).", "success")
        return redirect(url_for("dashboard"))

    # =========================================================
    # 📥 GET
    # =========================================================

    return render_template(
        "modifica_annuncio.html",
        modalita="modifica",
        annuncio=annuncio
    )

# --- Dashboard: carica anche i nuovi campi (sostituisci la tua dashboard() attuale) ---
@app.route('/utente/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    ut = conn.execute(sql("""
        SELECT id, nome, cognome, email, username, citta, lingue, frase,
               telefono, email_pubblica, indirizzo_studio,
               sito_web, instagram, facebook, linkedin,
               orari, preferenze_contatto,
               visibile_pubblicamente, visibile_in_chat,
               media_recensioni, numero_recensioni, foto_profilo, copertina, foto_galleria,
               offro_1, offro_2, offro_3, offro_4, offro_5, offro_6, offro_7, offro_8, offro_9, offro_10,
               cerco_1, cerco_2, cerco_3, cerco_4, cerco_5, cerco_6, cerco_7, cerco_8, cerco_9, cerco_10,
               esperienza_1, esperienza_2, esperienza_3,
               studio_1, studio_2, studio_3, certificazioni,
               descrizione
        FROM utenti
        WHERE id = ?
    """), (session["utente_id"],)).fetchone()



    # Se non trovato, gestisci come preferisci
    if not ut:
        flash("Utente non trovato.", "error")
        return redirect(url_for("home"))

    utente = dict(ut)
    # cast sicuro dei flag (possono essere None/0/1 o stringhe)
    for i in range(1, 11):
        utente[f"offro_{i}"] = int(utente.get(f"offro_{i}") or 0)
        utente[f"cerco_{i}"] = int(utente.get(f"cerco_{i}") or 0)

    # Calcoli recensioni
    media, totale = calcola_media_recensioni(utente['id'])

    # 🔹 Carica gli annunci dell'utente loggato
    conn = get_db_connection()

    c = get_cursor(conn)
    c.execute(sql("""
        SELECT id, titolo, categoria, descrizione, zona, filtri_categoria,
               data_pubblicazione, stato
        FROM annunci
        WHERE utente_id = ?
        ORDER BY data_pubblicazione DESC
    """), (session["utente_id"],))
    annunci = [dict(r) for r in c.fetchall()]


    # 🔹 Ritorna la dashboard con gli annunci caricati
    return render_template(
        'dashboard.html',
        utente=utente,
        user=g.utente,
        annunci=annunci,
        media_recensioni=media,
        totale_recensioni=totale,
        pubblico=False,
        page="profilo"
    )
# --- Aggiorna INFO (tab) ---
@app.route("/utente/update_info", methods=["POST"])
@login_required
def utente_update_info():
    user_id = session.get("utente_id")
    if not user_id:
        flash("Errore: sessione utente non valida.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    c = get_cursor(conn)

    # 🔹 Campi base
    citta = request.form.get("citta", "")
    citta = citta.strip()
    provincia = get_provincia_from_comune(citta) if citta else None
    lingue = request.form.get("lingue", "")
    frase = request.form.get("frase", "")
    descrizione = request.form.get("descrizione", "")
    telefono = request.form.get("telefono", "")
    indirizzo_studio = request.form.get("indirizzo_studio", "")
    sito_web = request.form.get("sito_web", "")
    instagram = request.form.get("instagram", "")
    facebook = request.form.get("facebook", "")
    linkedin = request.form.get("linkedin", "")
    orari = request.form.get("orari", "")
    preferenze_contatto = request.form.get("preferenze_contatto", "")
    # ✅ Non aggiornare mai "email" da questo form (non viene inviato)
    # ✅ email_pubblica: se nel form non c'è, la lasciamo invariata
    c.execute(sql("SELECT email, email_pubblica FROM utenti WHERE id = ?"), (user_id,))
    row = c.fetchone()
    email_db = list(row.values())[0] if row else ""
    email_pubblica_db = list(row.values())[1] if row else ""

    email = email_db  # resta quella vera dell’account

    email_pubblica_form = request.form.get("email_pubblica", "").strip()
    email_pubblica = email_pubblica_form if email_pubblica_form != "" else (email_pubblica_db or "")

    esperienza_1 = request.form.get("esperienza_1", "")
    esperienza_2 = request.form.get("esperienza_2", "")
    esperienza_3 = request.form.get("esperienza_3", "")
    studio_1 = request.form.get("studio_1", "")
    studio_2 = request.form.get("studio_2", "")
    studio_3 = request.form.get("studio_3", "")
    certificazioni = request.form.get("certificazioni", "")

    # 🔹 Checkbox attività — leggi l'ULTIMO valore (hidden "0" oppure checkbox "1")
    def _cb(name):
        vals = request.form.getlist(name)
        return int(vals[-1]) if vals else 0

    offro = [_cb(f"offro_{i}") for i in range(1, 11)]
    cerco = [_cb(f"cerco_{i}") for i in range(1, 11)]

    print("OFFRO:", [request.form.getlist(f"offro_{i}") for i in range(1,9)])
    print("CERCO:", [request.form.getlist(f"cerco_{i}") for i in range(1,9)])
    print("OFFRO RISOLTO:", offro)
    print("CERCO RISOLTO:", cerco)

    # 🔹 Query esplicita e completa
    # 🔹 Query SOLO per TAB "Info di base"
    query_update = """
        UPDATE utenti SET
            citta = ?,
            provincia = ?,
            lingue = ?,
            frase = ?,
            offro_1 = ?, offro_2 = ?, offro_3 = ?, offro_4 = ?, offro_5 = ?,
            offro_6 = ?, offro_7 = ?, offro_8 = ?, offro_9 = ?, offro_10 = ?,
            cerco_1 = ?, cerco_2 = ?, cerco_3 = ?, cerco_4 = ?, cerco_5 = ?,
            cerco_6 = ?, cerco_7 = ?, cerco_8 = ?, cerco_9 = ?, cerco_10 = ?
        WHERE id = ?
    """

    valori = (
        citta, provincia, lingue, frase,
        *offro, *cerco,
        user_id
    )

    try:
        c.execute(sql(query_update), valori)
        conn.commit()
        flash("✅ Modifiche salvate con successo.", "success")

        # 🔁 ALLINEA LA MACRO-AREA COME IN LANDING
        if citta:
            provincia = get_provincia_from_comune(citta)

            if provincia:
                session["macro_area"] = provincia
                session["macro_comune"] = citta

                # ⭐ SINCRONIZZA ANCHE IL DB
                conn2 = get_db_connection()
                conn2.execute(
                    "UPDATE utenti SET macro_area = ? WHERE id = ?",
                    (provincia, user_id)
                )
                conn2.commit()
                conn2.close()

    except Exception as e:
        conn.rollback()
        flash(f"Errore nel salvataggio: {e}", "error")
        print("❌ ERRORE SALVATAGGIO:", e)
    finally:
        try:
            conn.close()
        except:
            pass


    return redirect(url_for("dashboard"))

@app.route("/utente/update_esperienza", methods=["POST"])
@login_required
def utente_update_esperienza():
    print("🟢 FUNZIONE ATTIVATA /utente/update_esperienza")
    print("📘 DATI RICEVUTI:", dict(request.form))
    user_id = session.get("utente_id")
    if not user_id:
        flash("Sessione non valida.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    c = get_cursor(conn)

    esperienza_1 = request.form.get("esperienza_1", "")
    esperienza_2 = request.form.get("esperienza_2", "")
    esperienza_3 = request.form.get("esperienza_3", "")
    studio_1 = request.form.get("studio_1", "")
    studio_2 = request.form.get("studio_2", "")
    studio_3 = request.form.get("studio_3", "")
    certificazioni = request.form.get("certificazioni", "")

    print("📘 DATI RICEVUTI (Esperienza):", esperienza_1, esperienza_2, esperienza_3, studio_1, studio_2, studio_3, certificazioni)

    try:
        c.execute(sql("""
            UPDATE utenti SET
                esperienza_1 = ?, esperienza_2 = ?, esperienza_3 = ?,
                studio_1 = ?, studio_2 = ?, studio_3 = ?,
                certificazioni = ?
            WHERE id = ?
        """), (esperienza_1, esperienza_2, esperienza_3, studio_1, studio_2, studio_3, certificazioni, user_id))
        conn.commit()
        flash("✅ Esperienza e formazione aggiornate con successo.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Errore durante il salvataggio: {e}", "error")
    finally:
        try:
            conn.close()
        except:
            pass


    return redirect(url_for("dashboard") + "#tab-info")

# ---------------------------------------------------------
# 📞 AGGIORNA CONTATTI UTENTE
# ---------------------------------------------------------
@app.route("/utente/update_contatti", methods=["POST"])
@login_required
def utente_update_contatti():
    print("🟢 FUNZIONE ATTIVATA /utente/update_contatti")
    print("📘 DATI RICEVUTI:", dict(request.form))

    user_id = session.get("utente_id")
    conn = get_db_connection()
    c = get_cursor(conn)

    telefono = request.form.get("telefono", "")
    email_pubblica = request.form.get("email_pubblica", "")
    indirizzo_studio = request.form.get("indirizzo_studio", "")
    sito_web = request.form.get("sito_web", "")
    instagram = request.form.get("instagram", "")
    facebook = request.form.get("facebook", "")
    linkedin = request.form.get("linkedin", "")
    orari = request.form.get("orari", "")
    preferenze_contatto = request.form.get("preferenze_contatto", "")

    try:
        c.execute(sql("""
            UPDATE utenti SET
                telefono=?, email_pubblica=?, indirizzo_studio=?, sito_web=?,
                instagram=?, facebook=?, linkedin=?, orari=?, preferenze_contatto=?
            WHERE id=?
        """), (telefono, email_pubblica, indirizzo_studio, sito_web,
              instagram, facebook, linkedin, orari, preferenze_contatto, user_id))
        conn.commit()
        flash("✅ Contatti aggiornati con successo.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Errore durante il salvataggio dei contatti: {e}", "error")
    finally:
        try:
            conn.close()
        except:
            pass


    return redirect(url_for("dashboard"))

# ---------------------------------------------------------
# ✏️ AGGIORNA DESCRIZIONE UTENTE
# ---------------------------------------------------------
@app.route("/utente/update_descrizione", methods=["POST"])
@login_required
def utente_update_descrizione():
    print("🟢 FUNZIONE ATTIVATA /utente/update_descrizione")
    print("📘 DATI RICEVUTI:", dict(request.form))

    user_id = session.get("utente_id")
    if not user_id:
        flash("Sessione non valida.", "error")
        return redirect(url_for("login"))

    descrizione = request.form.get("descrizione", "").strip()

    conn = get_db_connection()
    c = get_cursor(conn)

    try:
        c.execute(sql("UPDATE utenti SET descrizione = ? WHERE id = ?"), (descrizione, user_id))
        conn.commit()
        flash("✅ Descrizione aggiornata con successo.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"❌ Errore durante il salvataggio della descrizione: {e}", "error")
    finally:
        try:
            conn.close()
        except:
            pass


    return redirect(url_for("dashboard") + "#tab-descrizione")


# --- Aggiorna GALLERIA (tab) ---
@app.route('/utente/update_galleria', methods=['POST'])
@login_required
def utente_update_galleria():
    print("🟢 FUNZIONE ATTIVATA /utente/update_galleria")
    print("📘 DATI RICEVUTI:", dict(request.form))
    print("📸 FILES:", request.files)

    conn = get_db_connection()
    c = get_cursor(conn)

    # --- Recupera galleria esistente ---
    c.execute(sql("SELECT foto_galleria FROM utenti WHERE id = ?"), (g.utente['id'],))
    row = c.fetchone()
    correnti = []
    if row and row['foto_galleria']:
        try:
            correnti = json.loads(row['foto_galleria'])
        except Exception:
            correnti = [p for p in row['foto_galleria'].split(',') if p.strip()]

    # --- Rimuovi selezionate ---
    to_remove = request.form.getlist("remove")
    correnti = [p for p in correnti if p not in to_remove]

    # --- Aggiungi nuove immagini ---
    uploaded_files = request.files.getlist("foto_galleria")
    upload_dir = os.path.join(app.root_path, "static", "uploads", "profili", "galleria")
    os.makedirs(upload_dir, exist_ok=True)

    for file in uploaded_files:
        if file and file.filename:
            estensione = file.filename.rsplit('.', 1)[-1].lower()
            if estensione not in {"jpg", "jpeg", "png", "gif", "webp"}:
                continue
            nome_file = f"u{g.utente['id']}_{uuid.uuid4().hex}.{estensione}"
            percorso = os.path.join(upload_dir, nome_file)
            file.save(percorso)
            correnti.append(f"uploads/profili/galleria/{nome_file}")

    # --- Salva nel DB (come JSON per maggiore flessibilità) ---
    c.execute(sql("UPDATE utenti SET foto_galleria = ? WHERE id = ?"), (json.dumps(correnti), g.utente['id']))
    conn.commit()


    flash("✅ Galleria aggiornata correttamente 📸", "success")
    return redirect(url_for("dashboard") + "#tab-foto")

@app.route("/annuncio/<int:id>/elimina")
@login_required
def elimina_annuncio(id):
    conn = get_db_connection()
    cur = get_cursor(conn)
    cur.execute(sql("SELECT * FROM annunci WHERE id = ?"), (id,))
    annuncio = cur.fetchone()

    if not annuncio or annuncio["utente_id"] != g.utente["id"]:

        flash("Non puoi eliminare questo annuncio.", "error")
        return redirect(url_for("dashboard"))

    conn.execute(sql("DELETE FROM annunci WHERE id = ?"), (id,))
    conn.commit()


    # 🔁 Se l'annuncio era 'in_attesa', i counters admin vanno aggiornati
    invalidate_admin_counters()

    flash("Annuncio eliminato con successo.", "success")
    return redirect(url_for("dashboard"))

# --- Foto Profilo ---

import werkzeug
from werkzeug.utils import secure_filename

# --- Configurazione cartella upload ---
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'profili')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --- Upload foto profilo ---
@app.route('/utente/foto', methods=['GET', 'POST'])
@login_required
def upload_foto():
    if request.method == 'POST':
        if 'foto' not in request.files:
            flash("Nessun file selezionato.")
            return redirect(request.url)

        file = request.files['foto']
        if file.filename == '':
            flash("Seleziona un file valido.")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(f"utente_{g.utente['id']}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            conn = get_db_connection()
            conn.execute(sql("UPDATE utenti SET foto_profilo = ? WHERE id = ?"), (f"uploads/profili/{filename}", g.utente['id']))
            conn.commit()


            flash("Foto profilo aggiornata con successo.")
            return redirect(url_for('dashboard'))
        else:
            flash("Formato file non valido. Usa JPG, PNG o GIF.")
            return redirect(request.url)

    return render_template('upload_foto.html', utente=g.utente)

# --- Upload copertina profilo ---
@app.route('/utente/copertina', methods=['POST'])
@login_required
def upload_copertina():
    if 'file' not in request.files:
        flash("Nessun file selezionato.")
        return redirect(request.referrer or url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash("Seleziona un file valido.")
        return redirect(request.referrer or url_for('dashboard'))

    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
    estensione = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else None

    if estensione not in ALLOWED_EXTENSIONS:
        flash("Formato non valido. Usa JPG, PNG o WEBP.")
        return redirect(request.referrer or url_for('dashboard'))

    upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'profili', 'copertine')
    os.makedirs(upload_dir, exist_ok=True)

    filename = f"copertina_{g.utente['id']}.{estensione}"
    file_path = os.path.join(upload_dir, filename)
    file.save(file_path)

    # Salva percorso nel DB
    conn = get_db_connection()
    conn.execute(sql("UPDATE utenti SET copertina = ? WHERE id = ?"), (f"uploads/profili/copertine/{filename}", g.utente['id']))
    conn.commit()


    flash("Copertina aggiornata con successo 📸", "success")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/rimuovi_copertina', methods=['POST'])
@login_required
def rimuovi_copertina():
    """Elimina la copertina profilo e ripristina il fondo azzurro di default"""
    user_id = g.utente['id']

    conn = get_db_connection()
    cur = get_cursor(conn)
    cur.execute(sql("SELECT copertina FROM utenti WHERE id = ?"), (user_id,))
    row = cur.fetchone()

    if row and row['copertina']:
        path = os.path.join(app.root_path, 'static', row['copertina'])
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                print(f"⚠️ Errore eliminando la copertina: {e}")

    conn.execute(sql("UPDATE utenti SET copertina = NULL WHERE id = ?"), (user_id,))
    conn.commit()


    flash("Copertina rimossa. Tornerà il fondo di default 💙", "info")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/utente/messaggi')
@login_required
def utente_messaggi():
    """Mostra solo le chat dirette tra utenti"""
    from models import chat_threads
    threads = chat_threads(g.utente['id'])
    return render_template('utente_messaggi.html', threads=threads, utente=g.utente)


# --- Pagina "I miei annunci" ---
@app.route('/utente/annunci')
@login_required
def utente_annunci():
    conn = get_db_connection()
    annunci = conn.execute(sql("""
        SELECT * FROM annunci
        WHERE utente_id = ?
        ORDER BY data_pubblicazione DESC
    """), (g.utente['id'],)).fetchall()

    return render_template('utente_annunci.html', annunci=annunci, utente=g.utente)
# ==========================================================
# RECENSIONI – AREA PERSONALE UTENTE
# ==========================================================
from models import get_recensioni_scritte, elimina_recensione

@app.route("/mie-recensioni")
@login_required
def mie_recensioni():
    """Mostra tutte le recensioni scritte dall’utente loggato"""
    user_id = g.utente["id"]
    recensioni = get_recensioni_scritte(user_id)

    # ✅ Recupera e svuota eventuali flash pendenti
    flashed = get_flashed_messages(with_categories=True)
    session.modified = True

    return render_template(
        "mie_recensioni.html",
        recensioni=recensioni,
        utente=g.utente,
        flashed=flashed
    )

@app.route("/elimina-recensione/<int:id>", methods=["POST"])
@login_required
def elimina_recensione_route(id):
    """Permette all’utente di eliminare una propria recensione"""
    elimina_recensione(id, id_autore=g.utente["id"])
    flash("Recensione eliminata con successo ✅", "success")
    return redirect(url_for("mie_recensioni"))

@app.route("/modifica_recensione", methods=["POST"])
@login_required
def modifica_recensione():
    from models import aggiungi_o_modifica_recensione

    id_recensione = request.form.get("id_recensione")
    testo = request.form.get("testo", "").strip()
    voto = int(request.form.get("voto", 0))

    # Recupera il destinatario della recensione
    conn = get_db_connection()
    c = get_cursor(conn)
    c.execute(sql("""
        SELECT id_destinatario
        FROM recensioni
        WHERE id = ? AND id_autore = ?
    """), (id_recensione, g.utente["id"]))
    row = c.fetchone()


    if not row:
        flash("Recensione non trovata o non autorizzata.", "error")
        return redirect(url_for("mie_recensioni"))

    id_destinatario = list(row.values())[0]

    # 🟦 DECISIONE AUTOMATICA DELLO STATO
    # - Se il testo è vuoto → la recensione è approvata subito
    # - Se c'è testo → deve essere moderata
    if testo == "":
        stato = "approvato"
    else:
        stato = "in_attesa"

    # 🟩 Usa la funzione di utility mantenendo stato coerente
    aggiungi_o_modifica_recensione(
        id_autore=g.utente["id"],
        id_destinatario=id_destinatario,
        voto=voto,
        testo=testo,
        stato=stato
    )

    # 🔔 Aggiorna counter admin solo se serve moderazione
    if stato == "in_attesa":
        invalidate_admin_counters()

    # 🔵 Messaggio coerente con stato scelto
    if stato == "approvato":
        flash("⭐ Recensione aggiornata con successo.", "success")
    else:
        flash("✏️ Modifica inviata e in attesa di approvazione.", "success")

    return redirect(url_for("mie_recensioni"))


# ==========================================================
# NOTIFICHE - ROTTE (AGGIUNTA)
# ==========================================================
@app.route('/notifiche')
@login_required
def notifiche():
    pulisci_notifiche_vecchie()  # 🧹 Mantiene pulito il DB
    notifiche = get_notifiche_utente(g.utente['id'])
    return render_template('notifiche.html', notifiche=notifiche)



@app.route('/recensioni-ricevute', methods=["GET", "POST"])
@login_required
def mie_recensioni_ricevute():
    user_id = session.get('utente_id')
    if not user_id:
        flash("Devi accedere per visualizzare le recensioni.")
        return redirect(url_for("login"))

    # --- POST: gestione invio/modifica/eliminazione risposta alla recensione ---
    if request.method == "POST":
        azione = request.form.get("azione")
        if azione == "rispondi":
            id_recensione = request.form.get("id_recensione", type=int)
            testo = (request.form.get("testo_risposta") or "").strip()
            if id_recensione and testo:
                try:
                    aggiungi_o_modifica_risposta(id_recensione, user_id, testo)
                    flash("✅ Risposta inviata! Sarà visibile dopo approvazione.", "success")
                    invalidate_admin_counters()
                except Exception as e:
                    flash(f"❌ Errore durante il salvataggio della risposta: {e}", "danger")
            else:
                flash("Testo della risposta mancante o ID non valido.", "warning")

        elif azione == "modifica_risposta":
            id_risposta = request.form.get("id_risposta", type=int)
            testo = (request.form.get("testo_risposta") or "").strip()
            if id_risposta and testo:
                try:
                    aggiungi_o_modifica_risposta(id_risposta=id_risposta, testo=testo)
                    flash("✏️ Risposta modificata con successo (in attesa di approvazione).", "info")
                    invalidate_admin_counters()
                except Exception as e:
                    flash(f"Errore durante la modifica: {e}", "danger")
            else:
                flash("Testo della risposta mancante o ID non valido.", "warning")

        return redirect(url_for("mie_recensioni_ricevute"))

    # --- GET: mostra statistiche + elenco recensioni ricevute ---
    recensioni = get_recensioni_utente(user_id)
    media, totale = calcola_media_recensioni(user_id)

    return render_template(
        "mie_recensioni_ricevute.html",
        recensioni=recensioni,
        media=media,
        totale=totale
    )

# 🔹 Recensioni pubbliche visibili nel profilo utente
from flask import get_flashed_messages

@app.route("/recensioni_utente/<int:user_id>", methods=["GET", "POST"])
def recensioni_utente(user_id):
    """Mostra o gestisce le recensioni ricevute da un utente (profilo pubblico)."""
    if "utente_id" not in session:
        flash("Devi accedere per vedere i dettagli del profilo.", "warning")
        return redirect(url_for("login", next=request.path))

    flashed = get_flashed_messages(with_categories=True)
    session.modified = True

    conn = get_db_connection()

    c = get_cursor(conn)

    # ✅ verifica utente
    c.execute(sql("""
        SELECT * FROM utenti
        WHERE id = ?
          AND sospeso = 0
          AND (disattivato_admin IS NULL OR disattivato_admin = 0)
          AND attivo = 1
    """), (user_id,))
    user = c.fetchone()
    if not user:

        flash("Utente non trovato.", "error")
        return redirect(url_for("cerca"))

    # ✅ POST: nuova recensione
    if request.method == "POST":
        if "utente_id" not in session:
            flash("Devi accedere per lasciare una recensione.", "warning")

            return redirect(url_for("login"))

        # 🔒 Blocca recensioni se l’utente non ha caricato una foto profilo
        autore_id = session.get("utente_id")
        c.execute(sql("SELECT foto_profilo FROM utenti WHERE id = ?"), (autore_id,))
        fp_row = c.fetchone()

        if not fp_row or not fp_row["foto_profilo"]:
            flash("Per lasciare una recensione devi prima caricare una foto profilo.", "warning")

            return redirect(url_for("dashboard"))  # modifica se la tua pagina profilo ha un nome diverso


        id_autore = session.get("utente_id")
        voto = int(request.form.get("voto", 0))
        testo = request.form.get("testo", "").strip()

        esistente = get_recensione_autore_vs_destinatario(id_autore, user_id)
        if esistente:
            flash("⚠️ Hai già lasciato una recensione per questo utente. Puoi solo modificarla.", "warning")

            return redirect(url_for("recensioni_utente", user_id=user_id))

        try:
            stato = "approvato" if not testo else "in_attesa"

            conn.execute(sql(f"""
                INSERT INTO recensioni (id_autore, id_destinatario, voto, testo, stato, data)
                VALUES (?, ?, ?, ?, ?, {now_sql()})
            """), (id_autore, user_id, voto, testo, stato))
            conn.commit()

            # ✅ notifica automatica se solo stelline
            if stato == "approvato":
                # recupera username autore
                c.execute(sql("SELECT username FROM utenti WHERE id = ?"), (id_autore,))
                row = c.fetchone()
                username_autore = row["username"] if row and row["username"] else "utente"

                # ✅ salva notifica DB
                crea_notifica(
                    user_id,
                    f"@{username_autore} ti ha lasciato una valutazione ⭐ {voto}/5",
                    link=url_for("mie_recensioni_ricevute")
                )

                # ✅ invio realtime Socket.IO (badge notifiche)
                emit_update_notifications(user_id)

                flash("⭐ Recensione salvata!", "success")

            else:
                flash("✅ Recensione inviata! Sarà visibile dopo approvazione.", "success")
                invalidate_admin_counters()

        except Exception as e:
            flash(f"❌ Errore durante il salvataggio della recensione: {e}", "error")

        finally:
            try:
                conn.close()
            except:
                pass


        return redirect(url_for("recensioni_utente", user_id=user_id))

    # ✅ GET: mostra recensioni
    recensioni = get_recensioni_utente(user_id)
    media, totale = calcola_media_recensioni(user_id)


    return render_template(
        "recensioni_utente.html",
        user=user,
        user_id=user_id,
        recensioni=recensioni,
        media=media,
        totale=totale,
        mia_recensione=None
    )


# ==========================================================
# 5️⃣ AUTENTICAZIONE
# ==========================================================
import json


def get_comune_info(comune_input):
    path = os.path.join(app.static_folder, "data", "comuni.json")

    with open(path, encoding="utf-8") as f:
        comuni = json.load(f)

    comune_input = comune_input.strip().lower()

    for c in comuni:
        if c["comune"].lower() == comune_input:
            return {
                "provincia": c.get("provincia"),
                "regione": c.get("regione")
            }

    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form['nome'].strip()
        cognome = request.form['cognome'].strip()
        citta = request.form['citta'].strip()
        email = request.form['email'].strip().lower()
        username = request.form['username'].strip().upper()
        password = request.form['password']
        conferma_password = request.form['conferma_password']
        accetto = request.form.get('accetto')
        codice_invito = request.form.get('codice_invito', '').strip()

        # ✅ Validazioni base
        if not accetto:
            flash("Devi accettare i termini e la privacy per continuare.")
            return redirect(url_for('register'))

        if password != conferma_password:
            flash("Le password non coincidono.")
            return redirect(url_for('register'))

        # 🔒 Codice beta obbligatorio
        CODICE_BETA = "LOCALCARE2026"   # ← puoi cambiarlo quando vuoi

        if codice_invito != CODICE_BETA:
            flash("Codice invito non valido.")
            return redirect(url_for('register'))

        # 🔎 Provincia dal JSON
        info = get_comune_info(citta)

        if not info:
            flash("Comune non valido. Selezionalo dall'elenco.")
            return redirect(url_for('register'))

        provincia = info["provincia"]
        regione = info["regione"]
        macro_area = provincia

        conn = get_db_connection()
        c = get_cursor(conn)

        # ✅ Controllo duplicati
        c.execute(sql("""
            SELECT * FROM utenti
            WHERE email = ?
               OR UPPER(username) = ?
        """), (email, username))

        existing_user = c.fetchone()
        if existing_user:
            if existing_user['email'] == email:
                flash("Questa email è già registrata.")
            else:
                flash("Questo ID utente è già in uso.")

            return redirect(url_for('register'))

        # 🔐 Sicurezza
        token = str(uuid.uuid4())
        hashed_pw = generate_password_hash(password)

        dek = get_random_bytes(32)
        dek_enc_b64, dek_nonce_b64 = encrypt_with_master(dek)
        salt_b64 = ""

        from nacl.public import PrivateKey
        x25519_priv = PrivateKey.generate()
        x25519_pub = x25519_priv.public_key

        cipher_priv = AES.new(dek, AES.MODE_GCM)
        priv_ct, priv_tag = cipher_priv.encrypt_and_digest(bytes(x25519_priv))

        x25519_priv_enc_b64 = gcm_pack(priv_ct, priv_tag)
        x25519_priv_nonce_b64 = base64.b64encode(cipher_priv.nonce).decode()
        x25519_pub_b64 = base64.b64encode(bytes(x25519_pub)).decode()

        # ✅ INSERT COMPLETO
        c.execute(sql("""
            INSERT INTO utenti (
                nome, cognome, email, username, password,
                citta, provincia, macro_area,
                attivo, token_verifica,
                key_salt, dek_enc, dek_nonce,
                dek_mk_enc, dek_mk_nonce,
                x25519_pub, x25519_priv_enc, x25519_priv_nonce,
                versione_consenso
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """), (
            nome, cognome, email, username, hashed_pw,
            citta, provincia, macro_area,
            0, token,
            salt_b64, dek_enc_b64, dek_nonce_b64,
            None, None,
            x25519_pub_b64, x25519_priv_enc_b64, x25519_priv_nonce_b64,
            "iubenda_2026_v1"
        ))

        conn.commit()


        # 📧 Email conferma
        link = build_external_url("conferma_email", token=token)

        messaggio = Message(
            'Conferma la tua registrazione su MyLocalCare',
            sender='MyLocalCare <info@mylocalcare.it>',
            recipients=[email]
        )

        html = render_template(
            "email/conferma_account.html",
            nome=nome,
            link=link
        )

        messaggio.html = html
        messaggio.body = f"Conferma il tuo account: {link}"

        threading.Thread(target=send_async_email, args=(app, messaggio), daemon=True).start()

        flash("Registrazione completata! Controlla la tua email per confermare l'account.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route("/termini")
def termini():
    return render_template("termini.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route('/conferma/<token>')
def conferma_email(token):
    conn = get_db_connection()
    c = get_cursor(conn)
    c.execute(sql("SELECT * FROM utenti WHERE token_verifica = ?"), (token,))
    utente = c.fetchone()

    if utente:
        c.execute(sql("UPDATE utenti SET attivo = 1, token_verifica = NULL WHERE id = ?"), (utente['id'],))
        conn.commit()

        # 🔔 Aggiunta: prima notifica all'utente
        crea_notifica(
            utente['id'],
            "📸 Completa il tuo profilo caricando una foto per essere visibile.",
            link=url_for('upload_foto')
        )
        flash("Email confermata! Ora puoi accedere.")
    else:
        flash("Token non valido o già usato.")


    return redirect(url_for('login'))

# ==========================================================
# 🔐 LOGIN UTENTE + DECIFRATURA CHIAVI PERSONALI
# (VERSIONE PROFILING — NON MODIFICA LOGICA)
# ==========================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    import time
    t_start = time.perf_counter()

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        # ===============================
        # DB SELECT UTENTE
        # ===============================
        conn = get_db_connection()
        c = get_cursor(conn)
        c.execute(sql("SELECT * FROM utenti WHERE email = ?"), (email,))
        utente = c.fetchone()

        t_select = time.perf_counter()
        print("⏱ SELECT utente:", round(t_select - t_start, 4), "sec")

        # 1️⃣ Utente inesistente
        if not utente:
            flash("Email o password non validi.", "error")
            return redirect(url_for('login'))

        # ---------------------------------------------------------
        # 🔐 BLOCCO LOCK
        # ---------------------------------------------------------
        from datetime import datetime, timezone

        def parse_iso(dt):
            if not dt:
                return None
            try:
                return datetime.fromisoformat(dt)
            except:
                return None

        lock_until = parse_iso(utente["lock_until"]) if "lock_until" in utente.keys() else None
        now = datetime.now(timezone.utc)

        if lock_until and lock_until > now:
            minuti = int((lock_until - now).total_seconds() // 60) + 1
            flash(f"Troppi tentativi falliti. Riprova tra {minuti} minuti.", "error")
            return redirect(url_for('login'))

        # Email non confermata
        if int(utente['attivo']) != 1:
            flash("Devi confermare l'email prima di accedere.", "warning")
            return redirect(url_for('login'))

        # ---------------------------------------------------------
        # PASSWORD CHECK
        # ---------------------------------------------------------
        if not check_password_hash(utente['password'], password):

            failed = (utente["failed_logins"] or 0) + 1
            lock_until = None

            if failed >= 5:
                from datetime import timedelta
                lock_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

            conn = get_db_connection()
            conn.execute(
                "UPDATE utenti SET failed_logins = ?, lock_until = ? WHERE id = ?",
                (failed, lock_until, utente["id"])
            )
            conn.commit()

            flash("Email o password non validi.", "error")
            return redirect(url_for('login'))

        t_pwd = time.perf_counter()
        print("⏱ password check:", round(t_pwd - t_select, 4), "sec")

        # ---------------------------------------------------------
        # STATUS CHECK
        # ---------------------------------------------------------
        disattivato_admin = utente['disattivato_admin'] if 'disattivato_admin' in utente.keys() else 0
        if disattivato_admin == 1:
            flash("Account disattivato.", "error")
            return redirect(url_for('login'))

        sospeso = utente['sospeso'] if 'sospeso' in utente.keys() else 0
        if sospeso == 1:
            session.clear()
            session['utente_id'] = utente['id']
            session['sospeso'] = True
            return redirect(url_for('riattivazione_account'))

        # ---------------------------------------------------------
        # MACRO AREA
        # ---------------------------------------------------------
        citta = utente["citta"]
        provincia = get_provincia_from_comune(citta)

        if provincia:
            session["macro_area"] = provincia
        else:
            session["macro_area"] = "Italia"

        t_geo = time.perf_counter()
        print("⏱ lookup provincia:", round(t_geo - t_pwd, 4), "sec")

        # ---------------------------------------------------------
        # DECRYPT MASTER (DEK)
        # ---------------------------------------------------------
        import base64

        try:
            dek = decrypt_with_master(utente['dek_enc'], utente['dek_nonce'])
            session['dek_b64'] = base64.b64encode(dek).decode()
        except Exception as e:
            print("Errore decrypt MASTER:", e)
            flash("Errore chiave personale.", "error")
            return redirect(url_for("login"))

        t_dek = time.perf_counter()
        print("⏱ decrypt DEK:", round(t_dek - t_geo, 4), "sec")

        # ---------------------------------------------------------
        # DECRYPT X25519
        # ---------------------------------------------------------
        try:
            x_priv_nonce = base64.b64decode(utente["x25519_priv_nonce"])
            x_priv_ct, x_priv_tag = gcm_unpack(utente["x25519_priv_enc"])

            cipher_xpriv = AES.new(dek, AES.MODE_GCM, nonce=x_priv_nonce)
            x_priv_bytes = cipher_xpriv.decrypt_and_verify(x_priv_ct, x_priv_tag)

            session["x25519_priv_b64"] = base64.b64encode(x_priv_bytes).decode()
            session["x25519_pub_b64"] = utente["x25519_pub"]

        except Exception as e:
            print("Errore decrypt X25519:", e)

        t_x = time.perf_counter()
        print("⏱ decrypt X25519:", round(t_x - t_dek, 4), "sec")

        # ---------------------------------------------------------
        # RESET FAIL LOGIN
        # ---------------------------------------------------------
        conn = get_db_connection()
        conn.execute(
            "UPDATE utenti SET failed_logins = 0, lock_until = NULL WHERE id = ?",
            (utente["id"],)
        )
        conn.commit()

        t_reset = time.perf_counter()
        print("⏱ reset failed:", round(t_reset - t_x, 4), "sec")

        # ---------------------------------------------------------
        # ADMIN SESSION
        # ---------------------------------------------------------
        from datetime import datetime, timedelta, timezone
        import secrets

        if utente["ruolo"] == "admin":
            session_token = secrets.token_hex(32)
            expiry = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()

            conn = get_db_connection()
            conn.execute(sql("""
                UPDATE utenti
                SET admin_session_token = ?, admin_session_expiry = ?
                WHERE id = ?
            """), (session_token, expiry, utente["id"]))
            conn.commit()

            session["admin_session_token"] = session_token

        browser_fingerprint = request.headers.get("User-Agent", "unknown")

        conn = get_db_connection()
        conn.execute(sql("""
            UPDATE utenti
            SET admin_browser_fingerprint = ?
            WHERE id = ?
        """), (browser_fingerprint, utente["id"]))
        conn.commit()

        session["admin_browser_fingerprint"] = browser_fingerprint

        t_admin = time.perf_counter()
        print("⏱ admin updates:", round(t_admin - t_reset, 4), "sec")

        # ---------------------------------------------------------
        # SESSION BASE
        # ---------------------------------------------------------
        session['utente_id'] = utente['id']
        session['utente_username'] = utente['username']

        ensure_x25519_keys(utente['id'])

        t_keys = time.perf_counter()
        print("⏱ ensure_x25519_keys:", round(t_keys - t_admin, 4), "sec")

        from flask import get_flashed_messages
        get_flashed_messages()

        flash("Accesso effettuato con successo.", "success")

        t_total = time.perf_counter()
        print("🔥 LOGIN TOTALE:", round(t_total - t_start, 4), "sec")

        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)

        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/password_dimenticata', methods=['GET', 'POST'])
def password_dimenticata():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email:
            flash("Inserisci un indirizzo email.", "error")
            return redirect(url_for('password_dimenticata'))

        # 🔎 Cerca utente
        conn = get_db_connection()

        cur = get_cursor(conn)
        cur.execute(sql("SELECT * FROM utenti WHERE email = ?"), (email,))
        utente = cur.fetchone()


        # ✅ Non riveliamo nulla
        if not utente:
            flash("Se l'email è registrata, riceverai un link per reimpostare la password.", "info")
            return redirect(url_for('password_dimenticata'))

        # ✅ Genera token sicuro firmato
        s = get_reset_serializer()
        token = s.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

        reset_url = url_for('reset_password', token=token, _external=True)

        # ✅ Salva token nel DB e invalida i precedenti
        conn = get_db_connection()
        cur = get_cursor(conn)

        # invalida eventuali token ancora aperti
        cur.execute(sql("""
            UPDATE password_reset_tokens
            SET usato = 1
            WHERE utente_id = ?
        """), (utente['id'],))

        # salva nuovo token
        cur.execute(sql("""
            INSERT INTO password_reset_tokens (utente_id, token, scadenza, usato)
            VALUES (?, ?, {epoch_now_sql()} + 3600, 0)
        """), (utente['id'], token))

        conn.commit()


        # ✅ Invia email
        try:
            msg = Message(
                subject="Reimposta la tua password - MyLocalCare",
                recipients=[email],
                sender=('MyLocalCare', app.config.get('MAIL_USERNAME'))
            )
            html = render_template(
                "email/reset_password.html",
                nome=utente["nome"],
                link=reset_url
            )

            msg.html = html
            msg.body = f"Reset password: {reset_url}"

            mail.send(msg)

        except Exception as e:
            print("Errore invio mail reset:", e)
            flash("Errore nell'invio dell'email. Riprova più tardi.", "error")
            return redirect(url_for('password_dimenticata'))

        flash("Se l'email è registrata, riceverai a breve un link per reimpostare la password.", "success")
        return redirect(url_for('login'))

    return render_template('password_dimenticata.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    s = get_reset_serializer()

    try:
        email = s.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=3600
        )
    except SignatureExpired:
        flash("Il link per reimpostare la password è scaduto. Richiedine uno nuovo.", "error")
        return redirect(url_for('password_dimenticata'))
    except BadSignature:
        flash("Link non valido o manomesso. Richiedi un nuovo link.", "error")
        return redirect(url_for('password_dimenticata'))

    # ✅ Verifica token non già usato
    conn = get_db_connection()

    cur = get_cursor(conn)
    cur.execute(sql("SELECT * FROM password_reset_tokens WHERE token = ? AND usato = 0"), (token,))
    token_row = cur.fetchone()

    if not token_row:

        flash("Questo link è già stato utilizzato o invalidato.", "error")
        return redirect(url_for('password_dimenticata'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        conferma = request.form.get('conferma_password', '')

        if not password or not conferma:
            flash("Compila entrambi i campi password.", "error")
            return redirect(url_for('reset_password', token=token))

        if password != conferma:
            flash("Le password non coincidono.", "error")
            return redirect(url_for('reset_password', token=token))

        if len(password) < 8:
            flash("La password deve avere almeno 8 caratteri.", "error")
            return redirect(url_for('reset_password', token=token))

        # ✅ Recupera utente
        cur.execute(sql("SELECT * FROM utenti WHERE email = ?"), (email,))
        utente = cur.fetchone()

        if not utente:

            flash("Errore interno. Contatta il supporto.", "error")
            return redirect(url_for('login'))

        # ✅ Aggiorna SOLO la password (le chiavi restano invariate)
        pwd_hash = generate_password_hash(password)
        cur.execute(sql("UPDATE utenti SET password = ? WHERE email = ?"), (pwd_hash, email))

        # ✅ Marca token come usato
        cur.execute(sql("UPDATE password_reset_tokens SET usato = 1 WHERE token = ?"), (token,))
        conn.commit()


        # ✅ Login automatico
        session.clear()
        session['utente_id'] = utente['id']
        session['utente_username'] = utente['username']

                # ✅ Ripristina chiavi crittografiche in sessione come nel login
        try:
            import base64
            from Crypto.Cipher import AES
            from app import decrypt_with_master, gcm_unpack

            # 🔐 Decifra DEK con MASTER_SECRET
            dek = decrypt_with_master(utente['dek_enc'], utente['dek_nonce'])
            session['dek_b64'] = base64.b64encode(dek).decode()

            # 🔐 Decifra chiave privata X25519
            x_nonce = base64.b64decode(utente["x25519_priv_nonce"])
            x_ct, x_tag = gcm_unpack(utente["x25519_priv_enc"])

            cipher_x = AES.new(dek, AES.MODE_GCM, nonce=x_nonce)
            x_priv_bytes = cipher_x.decrypt_and_verify(x_ct, x_tag)

            session["x25519_priv_b64"] = base64.b64encode(x_priv_bytes).decode()
            session["x25519_pub_b64"] = utente["x25519_pub"]

            # ✅ Garantisce presenza chiavi (crea se mancanti)
            from app import ensure_x25519_keys
            ensure_x25519_keys(utente['id'])

        except Exception as e:
            print("Errore ripristino chiavi post-reset:", e)


        flash("Password aggiornata con successo!", "success")
        return redirect(url_for('dashboard'))

    return render_template('reset_password.html', token=token)

@app.route("/debug_chiavi_x25519")
@login_required
def debug_chiavi_x25519():
    return jsonify({
        "utente": g.utente["username"],
        "pubblica_X25519": session.get("x25519_pub_b64"),
        "privata_X25519": session.get("x25519_priv_b64")[:40] + "..." if session.get("x25519_priv_b64") else None
    })


@app.route('/logout')
def logout():
    # 🔥 Caso: logout dopo sospensione → messaggio speciale
    if session.get("sospensione_logout"):
        session.clear()
        flash(
            "Il tuo account è stato sospeso. Per riattivarlo effettua l’accesso e ti verrà mostrata la pagina di riattivazione.",
            "warning"
        )
        return redirect(url_for('login'))

    # 🔵 Caso normale

    # 🧹 Reset token e fingerprint admin nel DB (solo se era loggato)
    if session.get("utente_id"):
        conn = get_db_connection()
        conn.execute(sql("""
            UPDATE utenti
            SET admin_session_token = NULL,
                admin_session_expiry = NULL,
                admin_browser_fingerprint = NULL
            WHERE id = ?
        """), (session["utente_id"],))
        conn.commit()


    session.pop("dek_b64", None)
    session.pop("id_priv_b64", None)
    session.pop("id_pub_b64", None)
    session.clear()

    flash('Sei uscito correttamente.', 'info')
    return redirect(url_for('login'))

# ==========================================================
# 6️⃣ ROTTE PUBBLICHE
# ==========================================================
@app.route('/', endpoint='home')
def landing():
    utente_id = session.get('utente_id')

    # 1️⃣ Se loggato → recupero macro_area dal DB
    if utente_id:
        conn = get_db_connection()
        cur = get_cursor(conn)
        cur.execute(sql("SELECT macro_area FROM utenti WHERE id = ?"), (utente_id,))
        row = cur.fetchone()


        if row and row["macro_area"]:
            session['macro_area'] = row["macro_area"]
            return redirect(url_for('home_v2'))

    # 2️⃣ Se non loggato ma ha già scelto macro_area
    if session.get('macro_area'):
        return redirect(url_for('home_v2'))

    # 3️⃣ Altrimenti mostra landing
    return render_template('landing.html')

@app.route('/home')
def home_v2():
    macro = session.get('macro_area') or "Milano"
    brand_name = f"{macro}Care"
    return render_template('home.html', brand_name=brand_name)

def get_provincia_from_comune(comune_input):
    path = os.path.join(app.static_folder, "data", "comuni.json")

    try:
        with open(path, encoding="utf-8") as f:
            comuni = json.load(f)
    except Exception:
        return None

    comune_norm = comune_input.strip().lower()

    for c in comuni:
        if c.get("comune", "").strip().lower() == comune_norm:
            # ⬅️ QUI
            return c.get("provincia_nome") or c.get("provincia")

    return None

@app.route('/set-macro-area', methods=['POST'])
def set_macro_area():
    comune = (request.form.get('macro_comune') or "").strip()

    if not comune:
        flash("Seleziona un comune dall’elenco per continuare.")
        return redirect(url_for('home'))  # ✅ NON landing

    provincia = get_provincia_from_comune(comune)
    if not provincia:
        flash("Comune non riconosciuto. Selezionalo dall’elenco.")
        return redirect(url_for('home'))  # ✅ NON landing

    # ✅ qui salvi sempre la PROVINCIA come macro_area
    session['macro_area'] = provincia

    # opzionale: se vuoi salvarla davvero
    regione = (request.form.get('macro_regione') or "").strip()
    if regione:
        session['macro_regione'] = regione

    return redirect(url_for('home_v2'))

from flask import request, render_template, session
import sqlite3, json, time

@app.route("/cerca")
def cerca():
    # 🔒 BLOCCO BETA — accesso solo utenti registrati
    if not session.get("utente_id"):
        flash(
            "MyLocalCare è attualmente in fase BetaTest privata. "
            "Registrati per ottenere l’accesso anticipato.",
            "warning"
        )
        return redirect(url_for("home"))

    raw_cat = request.args.get("categoria", "").strip()
    cat_slug = to_slug(raw_cat)

    json_key = cat_slug
    categoria_label = raw_cat

    zona = request.args.get("zona", "").strip()
    provincia_filtro = request.args.get("provincia", "").strip()
    filtri_attivi = request.args.getlist("filtri")

    # 🔹 NUOVO: tipo annuncio (offro / cerco)
    tipo_annuncio = request.args.get("tipo_annuncio", "").strip().lower()
    if tipo_annuncio not in ("offro", "cerco"):
        tipo_annuncio = ""

    # =========================================================
    # 🔒 PROVINCIA BASE (macro area)
    # =========================================================
    provincia_attiva = session.get("macro_area")

    if not provincia_attiva:
        utente_id = session.get("utente_id")
        if utente_id:
            conn_tmp = get_db_connection()
            cur_tmp = conn_tmp.cursor()
            cur_tmp.execute(sql("SELECT provincia FROM utenti WHERE id = ?"), (utente_id,))
            row = cur_tmp.fetchone()
            conn_tmp.close()

            if row and list(row.values())[0]:
                provincia_attiva = list(row.values())[0]
                session["macro_area"] = provincia_attiva

    provincia_query = provincia_filtro or provincia_attiva or "__INVALID__"

    # =========================================================
    # FILTRI CATEGORIA
    # =========================================================
    with open("static/data/filtri_categoria.json", "r", encoding="utf-8") as f:
        filtri_per_categoria = json.load(f)

    filtri_possibili = filtri_per_categoria.get(json_key, [])

    # =========================================================
    # DB
    # =========================================================
    conn = get_db_connection()

    c = get_cursor(conn)

    # =========================================================
    # SQL FLAGS (DEVONO STARE PRIMA DI ESSERE USATE)
    # =========================================================
    has_urgente_sql = f"""
    (
      CASE WHEN EXISTS (
        SELECT 1
        FROM attivazioni_servizi act
        JOIN servizi s ON s.id = act.servizio_id
        WHERE act.annuncio_id = a.id
          AND s.codice = 'annuncio_urgente'
          AND act.stato = 'attivo'
          AND act.data_inizio <= {now_sql()}
          AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
      ) THEN 1 ELSE 0 END
    ) AS has_urgente
    """

    affidabilita_top_sql = """
        CASE
          WHEN EXISTS (
            SELECT 1
            FROM attivazioni_servizi act
            JOIN servizi s ON s.id = act.servizio_id
            WHERE s.codice = 'badge_affidabilita'
              AND act.utente_id = a.utente_id
              AND act.stato = 'attivo'
          ) THEN 1
          WHEN
            COALESCE((
              SELECT AVG(r.voto)
              FROM recensioni r
              WHERE r.id_destinatario = a.utente_id
                AND r.stato = 'approvato'
            ), 0) >= 4.2
          AND
            COALESCE((
              SELECT COUNT(*)
              FROM recensioni r
              WHERE r.id_destinatario = a.utente_id
                AND r.stato = 'approvato'
            ), 0) >= 5
          THEN 1
          ELSE 0
        END AS affidabilita_top
    """

    # =========================================================
    # 🟡 VETRINA – ROTAZIONE CICLICA INVERSA (30s)
    # =========================================================
    bucket = int(time.time() // 30)

    query_vetrina = f"""
        SELECT
            a.*,
            u.id AS utente_id,
            u.username AS utente_username,
            u.nome AS nome_utente,
            u.cognome AS cognome_utente,
            u.foto_profilo,

            {has_urgente_sql},
            {affidabilita_top_sql},

            COALESCE(ROUND((
                SELECT AVG(r.voto)
                FROM recensioni r
                WHERE r.id_destinatario = a.utente_id
                  AND r.stato = 'approvato'
            ), 1), 0) AS media_recensioni,

            COALESCE((
                SELECT COUNT(*)
                FROM recensioni r
                WHERE r.id_destinatario = a.utente_id
                  AND r.stato = 'approvato'
            ), 0) AS numero_recensioni

        FROM annunci a
        JOIN utenti u ON a.utente_id = u.id
        JOIN attivazioni_servizi act ON act.annuncio_id = a.id
        JOIN servizi s ON s.id = act.servizio_id
        WHERE
            s.codice = 'vetrina_annuncio'
            AND act.stato = 'attivo'
            AND act.data_inizio <= {now_sql()}
            AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
            AND a.stato = 'approvato'
            AND u.attivo = 1
            AND u.sospeso = 0
            AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
            AND a.provincia = ?
    """

    params_vetrina = [provincia_query]

    if json_key:
        query_vetrina += " AND a.categoria = ?"
        params_vetrina.append(json_key)

    if tipo_annuncio:
        query_vetrina += " AND a.tipo_annuncio = ?"
        params_vetrina.append(tipo_annuncio)

    if zona:
        query_vetrina += " AND a.zona LIKE ?"
        params_vetrina.append(f"%{zona}%")

    for f_att in filtri_attivi:
        query_vetrina += " AND a.filtri_categoria LIKE ?"
        params_vetrina.append(f"%{f_att}%")

    query_vetrina += " ORDER BY a.id ASC"

    c.execute(sql(query_vetrina), params_vetrina)
    rows = [dict(r) for r in c.fetchall()]

    annunci_vetrina = []
    n = len(rows)
    if n > 0:
        shift = bucket % n
        annunci_vetrina = (rows[-shift:] + rows[:-shift])[:6]

    # =========================================================
    # 🔥 BOOST SCORE – LISTA
    # =========================================================
    urgent_score_sql = f"""
    (
      CASE WHEN EXISTS (
        SELECT 1
        FROM attivazioni_servizi act
        JOIN servizi s ON s.id = act.servizio_id
        WHERE act.annuncio_id = a.id
          AND s.codice = 'annuncio_urgente'
          AND act.stato = 'attivo'
          AND act.data_inizio <= {now_sql()}
          AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
      ) THEN 200 ELSE 0 END
    ) AS urgent_score
    """
    boost_score_sql = f"""
    (
      CASE WHEN EXISTS (
        SELECT 1
        FROM attivazioni_servizi act
        JOIN servizi s ON s.id = act.servizio_id
        WHERE act.annuncio_id = a.id
          AND s.codice = 'boost_lista'
          AND act.stato = 'attivo'
          AND act.data_inizio <= {now_sql()}
          AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
      ) THEN 100 ELSE 0 END
    ) AS boost_score
    """
    has_evidenza_sql = f"""
    (
      CASE WHEN EXISTS (
        SELECT 1
        FROM attivazioni_servizi act
        JOIN servizi s ON s.id = act.servizio_id
        WHERE act.annuncio_id = a.id
          AND s.codice = 'badge_evidenza'
          AND act.stato = 'attivo'
          AND act.data_inizio <= {now_sql()}
          AND (act.data_fine IS NULL OR act.data_fine > {now_sql()})
      ) THEN 1 ELSE 0 END
    ) AS has_evidenza
    """

    query_annunci = f"""
        SELECT *
        FROM (
            SELECT
                a.*,
                u.id AS utente_id,
                u.username AS utente_username,
                u.nome AS nome_utente,
                u.cognome AS cognome_utente,
                u.email AS email_utente,
                u.foto_profilo,
                {urgent_score_sql},
                {boost_score_sql},
                {has_evidenza_sql},
                {has_urgente_sql},
                {affidabilita_top_sql},
                COALESCE(ROUND((
                    SELECT AVG(r.voto)
                    FROM recensioni r
                    WHERE r.id_destinatario = a.utente_id
                      AND r.stato = 'approvato'
                ), 1), 0) AS media_recensioni,
                COALESCE((
                    SELECT COUNT(*)
                    FROM recensioni r
                    WHERE r.id_destinatario = a.utente_id
                      AND r.stato = 'approvato'
                ), 0) AS numero_recensioni
            FROM annunci a
            JOIN utenti u ON a.utente_id = u.id
            WHERE a.stato = 'approvato'
              AND u.attivo = 1
              AND u.sospeso = 0
              AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
              AND u.foto_profilo IS NOT NULL
              AND u.foto_profilo != ''
              AND (u.ruolo IS NULL OR u.ruolo != 'admin')
              AND a.provincia = ?
    """

    params = [provincia_query]

    if json_key:
        query_annunci += " AND a.categoria = ?"
        params.append(json_key)

    if tipo_annuncio:
        query_annunci += " AND a.tipo_annuncio = ?"
        params.append(tipo_annuncio)

    if zona:
        query_annunci += " AND a.zona LIKE ?"
        params.append(f"%{zona}%")

    for f_att in filtri_attivi:
        query_annunci += " AND a.filtri_categoria LIKE ?"
        params.append(f"%{f_att}%")

    # 🔒 CHIUSURA SUBQUERY + ORDER BY ESTERNO (PostgreSQL safe)
    query_annunci += """
        ) sub
        ORDER BY
          CASE
            WHEN urgent_score > 0 THEN 0
            WHEN boost_score > 0 THEN 1
            ELSE 2
          END ASC,

          CASE
            WHEN urgent_score > 0 OR boost_score > 0
            THEN (abs(id * 1103515245 + 12345) %% 97)
            ELSE NULL
          END ASC,

          data_pubblicazione DESC,
          affidabilita_top DESC
    """

    c.execute(sql(query_annunci), params)
    annunci = [dict(row) for row in c.fetchall()]


    return render_template(
        "cerca.html",
        categoria=json_key,
        categoria_label=categoria_label,
        zona=zona,
        filtri=filtri_attivi,
        tipo_annuncio=tipo_annuncio,
        annunci_vetrina=annunci_vetrina,
        annunci=annunci,
        filtri_possibili=filtri_possibili,
    )

@app.route("/notifica/<int:id>/apri")
@login_required
def apri_notifica(id):
    conn = get_db_connection()
    notifica = conn.execute(
        "SELECT link FROM notifiche WHERE id = ? AND id_utente = ?",
        (id, g.utente["id"])
    ).fetchone()
    if not notifica:
        flash("Notifica non trovata.", "error")
        return redirect(url_for("notifiche"))

    # Segna come letta
    conn.execute(sql("UPDATE notifiche SET letta = 1 WHERE id = ?"), (id,))
    conn.commit()


    # 🔔 aggiorna il badge
    emit_update_notifications(g.utente["id"])

    # Reindirizza al link
    if notifica["link"]:
        return redirect(notifica["link"])
    else:
        return redirect(url_for("notifiche"))

@app.route("/elimina-risposta/<int:id>", methods=["POST"])
@login_required
def elimina_risposta_route(id):
    elimina_risposta(id, id_autore=g.utente["id"])
    flash("Risposta eliminata con successo ✅", "success")
    return redirect(request.referrer or url_for("mie_recensioni_ricevute"))

@app.route('/api/operatori')
def api_operatori():
    categoria = request.args.get('categoria', '').strip()
    zona = request.args.get('zona')
    operatori = [dict(op) for op in get_operatori(categoria, zona)]
    return jsonify(operatori)

@app.route('/api/operatore/<int:id>')
def api_operatore(id):
    op = get_operatore_by_id(id)
    if op:
        return jsonify(dict(op)), 200
    return jsonify({"error": "Not found"}), 404

@app.route("/api/suggerimenti-comuni")
def suggerimenti_comuni():
    q = (request.args.get("q") or "").strip().lower()
    if len(q) < 2:
        return jsonify([])

    path = os.path.join(app.static_folder, "data", "comuni.json")

    try:
        with open(path, encoding="utf-8") as f:
            comuni = json.load(f)
    except Exception:
        return jsonify([])

    risultati = []

    # 1️⃣ MATCH CHE INIZIANO PER (Roma, Milano, ecc.)
    for c in comuni:
        nome = c.get("comune", "")
        if nome.lower().startswith(q):
            risultati.append({
                "comune": nome,
                "provincia": c.get("provincia"),
                "regione": c.get("regione")
            })

    # 2️⃣ MATCH CHE CONTENGONO (solo se servono)
    if len(risultati) < 10:
        for c in comuni:
            nome = c.get("comune", "")
            nome_lower = nome.lower()

            if q in nome_lower and not nome_lower.startswith(q):
                risultati.append({
                    "comune": nome,
                    "provincia": c.get("provincia"),
                    "regione": c.get("regione")
                })

            if len(risultati) >= 10:
                break

    return jsonify(risultati[:10])

@app.route("/api/servizi/<codice>/piani")
@login_required
def api_servizi_piani(codice):
    conn = get_db_connection()
    cur = get_cursor(conn)

    # servizio
    cur.execute(sql("""
        SELECT id, nome, descrizione
        FROM servizi
        WHERE codice = ? AND attivo = 1
    """), (codice,))
    servizio = cur.fetchone()

    if not servizio:
        return jsonify({"error": "Servizio non trovato"}), 404

    # piani
    cur.execute(sql("""
        SELECT
            id,
            durata_giorni,
            prezzo_cent,
            consigliato,
            evidenziato
        FROM servizi_piani
        WHERE servizio_id = ?
          AND attivo = 1
        ORDER BY ordine ASC, prezzo_cent ASC
    """), (servizio["id"],))

    piani = [
        {
            "id": r["id"],
            "durata": r["durata_giorni"],   # NULL → permanente
            "prezzo": r["prezzo_cent"],
            "consigliato": r["consigliato"],
            "evidenziato": r["evidenziato"],
            "permanente": r["durata_giorni"] is None
        }
        for r in cur.fetchall()
    ]



    return jsonify({
        "servizio": {
            "id": servizio["id"],
            "nome": servizio["nome"],
            "descrizione": servizio["descrizione"]
        },
        "piani": piani
    })

@app.route("/api/annunci/<int:annuncio_id>/servizi/<codice>")
@login_required
def api_annuncio_servizio_stato(annuncio_id, codice):
    conn = get_db_connection()
    cur = get_cursor(conn)

    # servizio
    cur.execute(sql(f"""
        SELECT id, ambito
        FROM servizi
        WHERE codice = ? AND attivo = 1
    """), (codice,))
    servizio = cur.fetchone()

    if not servizio:

        return jsonify({"error": "Servizio non trovato"}), 404

    # query dinamica in base all’ambito
    if servizio["ambito"] == "profilo":
        cur.execute(sql(f"""
            SELECT
                id,
                data_inizio,
                data_fine,
                stato,
                attivato_da
            FROM attivazioni_servizi
            WHERE servizio_id = ?
              AND utente_id = ?
              AND annuncio_id IS NULL
            ORDER BY {order_datetime("data_inizio")} DESC
            LIMIT 1
        """), (servizio["id"], g.utente["id"]))
    else:
        cur.execute(sql(f"""
            SELECT
                id,
                data_inizio,
                data_fine,
                stato,
                attivato_da
            FROM attivazioni_servizi
            WHERE servizio_id = ?
              AND annuncio_id = ?
              AND utente_id = ?
            ORDER BY {order_datetime("data_inizio")} DESC
            LIMIT 1
        """), (servizio["id"], annuncio_id, g.utente["id"]))

    att = cur.fetchone()


    if not att:
        return jsonify({
            "attivo": False,
            "stato": "non_attivo",
            "data_inizio": None,
            "data_fine": None,
            "permanente": False
        })

    is_attivo = att["stato"] == "attivo"

    def solo_data(v):
        if not v:
            return None
        return str(v)[:10]

    return jsonify({
        "attivo": is_attivo,
        "stato": att["stato"],
        "data_inizio": solo_data(att["data_inizio"]) if is_attivo else None,
        "data_fine": solo_data(att["data_fine"]) if is_attivo else None,
        "permanente": is_attivo and not att["data_fine"],
        "attivato_da": att["attivato_da"]
    })

@app.route("/api/pacchetti/<codice>/piani")
@login_required
def api_pacchetti_piani(codice):
    conn = get_db_connection()
    cur = get_cursor(conn)

    # pacchetto
    cur.execute(sql("""
        SELECT id, nome, descrizione
        FROM pacchetti
        WHERE codice = ? AND attivo = 1
    """), (codice,))
    pacchetto = cur.fetchone()

    if not pacchetto:

        return jsonify({"error": "Pacchetto non trovato"}), 404

    # piani pacchetto
    cur.execute(sql("""
        SELECT
            id,
            durata_giorni,
            prezzo_cent,
            consigliato,
            evidenziato
        FROM pacchetti_piani
        WHERE pacchetto_id = ?
          AND attivo = 1
        ORDER BY ordine ASC, prezzo_cent ASC
    """), (pacchetto["id"],))

    piani = [
        {
            "id": r["id"],
            "durata": r["durata_giorni"],   # NULL → permanente
            "prezzo": r["prezzo_cent"],
            "consigliato": r["consigliato"],
            "evidenziato": r["evidenziato"],
            "permanente": r["durata_giorni"] is None
        }
        for r in cur.fetchall()
    ]



    return jsonify({
        "pacchetto": {
            "id": pacchetto["id"],
            "nome": pacchetto["nome"],
            "descrizione": pacchetto["descrizione"]
        },
        "piani": piani
    })

@app.route("/api/attiva", methods=["POST"])
@login_required
def api_attiva():
    data = request.get_json()

    annuncio_id = data.get("annuncio_id")
    piano_id = data.get("piano_id")
    tipo = data.get("tipo")  # "servizi" | "pacchetti"

    if not annuncio_id or not piano_id or tipo not in ("servizi", "pacchetti"):
        return jsonify({"error": "Dati non validi"}), 400

    conn = get_db_connection()

    cur = get_cursor(conn)

    try:
        # 1️⃣ recupero piano + prezzo
        if tipo == "servizi":
            cur.execute(sql("""
                SELECT p.id, p.prezzo_cent
                FROM servizi_piani p
                WHERE p.id = ? AND p.attivo = 1
            """), (piano_id,))
        else:
            cur.execute(sql("""
                SELECT p.id, p.prezzo_cent
                FROM pacchetti_piani p
                WHERE p.id = ? AND p.attivo = 1
            """), (piano_id,))

        piano = cur.fetchone()
        if not piano:
            return jsonify({"error": "Piano non valido"}), 404

        prezzo = int(piano["prezzo_cent"])
        if prezzo <= 0:
            return jsonify({"error": "Prezzo non valido"}), 400

        # 2️⃣ crea acquisto (pending)
        # 🔴 COSTRUZIONE DATI ACQUISTO (STANDARD UNICO)

        if tipo == "servizi":
            tipo_acquisto = "servizio"
            ref_id = piano_id   # per servizi: id del piano
        else:
            tipo_acquisto = "pacchetto"
            cur.execute(sql("""
                SELECT pacchetto_id
                FROM pacchetti_piani
                WHERE id = ?
            """), (piano_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Pacchetto non valido"}), 400
            ref_id = row["pacchetto_id"]

        # ✅ INSERT COMPLETO (UGUALE A crea-payment-intent)
        acquisto_id = insert_and_get_id(
            cur,
            """
            INSERT INTO acquisti
            (
                utente_id,
                tipo,
                ref_id,
                prezzo_id,
                metodo,
                importo_cent,
                stato,
                annuncio_id,
                created_at
            )
            VALUES (?, ?, ?, ?, 'stripe', ?, 'pending', ?, {now_sql()})
            """,
            (
                g.utente["id"],
                tipo_acquisto,
                ref_id,
                piano_id,
                prezzo,
                annuncio_id
            )
        )

        # 3️⃣ PaymentIntent Stripe
        intent = stripe.PaymentIntent.create(
            amount=prezzo,
            currency="eur",
            automatic_payment_methods={"enabled": True},
            metadata={
                "acquisto_id": acquisto_id,
                "piano_id": piano_id,
                "tipo": tipo,
                "annuncio_id": annuncio_id,
                "utente_id": g.utente["id"]
            }
        )

        # 4️⃣ salva riferimento Stripe
        cur.execute(sql("""
            UPDATE acquisti
            SET riferimento_esterno = ?
            WHERE id = ?
        """), (intent.id, acquisto_id))

        conn.commit()

        return jsonify({
            "ok": True,
            "client_secret": intent.client_secret
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        try:
            conn.close()
        except:
            pass



@app.route("/api/crea-payment-intent", methods=["POST"])
@login_required
def crea_payment_intent():
    data = request.get_json()

    annuncio_id = data.get("annuncio_id")
    piano_id = data.get("piano_id")
    tipo = data.get("tipo")  # "servizi" | "pacchetti"

    if not annuncio_id or not piano_id or tipo not in ("servizi", "pacchetti"):
        return jsonify({"error": "Dati non validi"}), 400

    conn = get_db_connection()

    cur = get_cursor(conn)

    try:
        if tipo == "servizi":
            cur.execute(sql("""
                SELECT id, prezzo_cent
                FROM servizi_piani
                WHERE id = ? AND attivo = 1
            """), (piano_id,))
            piano = cur.fetchone()
            if not piano:
                return jsonify({"error": "Piano servizio non trovato"}), 404

            tipo_acquisto = "servizio"
            ref_id = piano["id"]

        else:
            cur.execute(sql("""
                SELECT pacchetto_id, prezzo_cent
                FROM pacchetti_piani
                WHERE id = ? AND attivo = 1
            """), (piano_id,))
            piano = cur.fetchone()
            if not piano:
                return jsonify({"error": "Piano pacchetto non trovato"}), 404

            tipo_acquisto = "pacchetto"
            ref_id = piano["pacchetto_id"]

        prezzo = int(piano["prezzo_cent"])

        # crea acquisto locale (stato: creato)
        acquisto_id = insert_and_get_id(
            cur,
            """
            INSERT INTO acquisti
            (utente_id, tipo, ref_id, prezzo_id, metodo, importo_cent, stato, annuncio_id, created_at)
            VALUES (?, ?, ?, ?, 'stripe', ?, 'creato', ?, {now_sql()})
            """,
            (
                g.utente["id"],
                tipo_acquisto,
                ref_id,
                piano_id,
                prezzo,
                annuncio_id
            )
        )

        conn.commit()

    finally:
        try:
            conn.close()
        except:
            pass


    # PaymentIntent Stripe
    intent = stripe.PaymentIntent.create(
        amount=prezzo,
        currency="eur",
        metadata={
            "acquisto_id": acquisto_id
        }
    )

    return jsonify({
        "client_secret": intent.client_secret
    })

def gestisci_pagamento_confermato(payment_intent):
    riferimento_esterno = payment_intent.get("id")
    metadata = payment_intent.get("metadata", {}) or {}
    acquisto_id = metadata.get("acquisto_id")

    if not acquisto_id:
        print("❌ Webhook Stripe: metadata.acquisto_id mancante", metadata)
        return

    conn = get_db_connection()

    cur = get_cursor(conn)

    try:
        # lock di scrittura
        cur.execute(sql("BEGIN IMMEDIATE"))

        # fonte di verità: l’acquisto
        cur.execute(sql("""
            SELECT id, utente_id, tipo, ref_id, prezzo_id, stato, annuncio_id
            FROM acquisti
            WHERE id = ?
        """), (int(acquisto_id),))
        acquisto = cur.fetchone()

        if not acquisto:
            print("❌ Webhook Stripe: acquisto non trovato:", acquisto_id)
            conn.rollback()
            return

        # idempotenza
        if acquisto["stato"] == "paid":
            conn.rollback()
            return

        utente_id = int(acquisto["utente_id"])
        tipo = acquisto["tipo"]                  # 'servizio' | 'pacchetto'
        ref_id = int(acquisto["ref_id"])         # servizio: id piano servizi_piani | pacchetto: pacchetto_id
        piano_id = acquisto["prezzo_id"]         # piano scelto e pagato (id servizi_piani o pacchetti_piani)
        annuncio_id = acquisto["annuncio_id"]
        if annuncio_id is not None:
            annuncio_id = int(annuncio_id)

        # aggiorna acquisto
        cur.execute(sql("""
            UPDATE acquisti
            SET stato = 'paid',
                metodo = 'stripe',
                riferimento_esterno = ?
            WHERE id = ?
        """), (riferimento_esterno, int(acquisto_id)))

        # ===============================
        # SERVIZIO SINGOLO
        # ===============================
        if tipo == "servizio":
            # Nel tuo flusso attuale ref_id = servizi_piani.id
            # (ma per sicurezza, usiamo piano_id se presente)
            piano_servizio_id = int(piano_id) if piano_id is not None else int(ref_id)

            cur.execute(sql("""
                SELECT servizio_id, durata_giorni, prezzo_cent
                FROM servizi_piani
                WHERE id = ?
            """), (piano_servizio_id,))
            piano = cur.fetchone()
            if not piano:
                raise Exception("Piano servizio non trovato")

            # storico acquisto servizio
            cur.execute(sql("""
                INSERT INTO acquisti_servizi
                (utente_id, servizio_id, metodo, importo, valuta, riferimento_esterno)
                VALUES (?, ?, 'stripe', ?, 'EUR', ?)
            """), (
                utente_id,
                int(piano["servizio_id"]),
                float(int(piano["prezzo_cent"]) / 100.0),
                riferimento_esterno
            ))

            ok, msg, att_id = attiva_servizio(
                conn=conn,
                utente_id=utente_id,
                servizio_id=int(piano["servizio_id"]),
                annuncio_id=annuncio_id,
                durata_giorni=piano["durata_giorni"],  # ✅ dal piano
                acquisto_id=int(acquisto_id),
                attivato_da="stripe",
                note=f"Stripe PI {riferimento_esterno}"
            )

            print("ATTIVA SERVIZIO:", ok, msg, att_id)
            if not ok:
                raise Exception(msg)

        # ===============================
        # PACCHETTO
        # ===============================
        elif tipo == "pacchetto":
            if piano_id is None:
                raise Exception("piano_id mancante su acquisti.prezzo_id (impossibile determinare durata pacchetto)")

            # ✅ durata e prezzo TOT dal piano PACCHETTO PAGATO
            cur.execute(sql("""
                SELECT durata_giorni, prezzo_cent
                FROM pacchetti_piani
                WHERE id = ?
            """), (int(piano_id),))
            piano_p = cur.fetchone()
            if not piano_p:
                raise Exception("Piano pacchetto non trovato")

            durata_piano = piano_p["durata_giorni"]   # può essere NULL => permanente
            prezzo_tot_cent = int(piano_p["prezzo_cent"] or 0)

            # ✅ servizi reali del pacchetto (senza usare durata default!)
            cur.execute(sql("""
                SELECT servizio_id
                FROM pacchetti_servizi
                WHERE pacchetto_id = ?
            """), (ref_id,))
            servizi = cur.fetchall()

            if not servizi:
                raise Exception("Pacchetto senza servizi")

            quota = (prezzo_tot_cent / 100.0) / max(len(servizi), 1)

            for row in servizi:
                servizio_id = int(row["servizio_id"])

                # storico acquisto servizio (quota)
                cur.execute(sql("""
                    INSERT INTO acquisti_servizi
                    (utente_id, servizio_id, metodo, importo, valuta, riferimento_esterno)
                    VALUES (?, ?, 'stripe', ?, 'EUR', ?)
                """), (
                    utente_id,
                    servizio_id,
                    float(quota),
                    riferimento_esterno
                ))

                ok, msg, att_id = attiva_servizio(
                    conn=conn,
                    utente_id=utente_id,
                    servizio_id=servizio_id,
                    annuncio_id=annuncio_id,
                    durata_giorni=durata_piano,  # ✅ SOLO durata del piano pagato
                    acquisto_id=int(acquisto_id),
                    attivato_da="stripe",
                    note=f"Stripe PI {riferimento_esterno} (pacchetto)"
                )

                print("ATTIVA SERVIZIO PACCHETTO:", ok, msg, att_id)

                # caso legale: servizio permanente già attivo → non è errore
                if not ok and msg == "Servizio già attivo.":
                    continue

                if not ok:
                    raise Exception(msg)

        else:
            raise Exception("Tipo acquisto non valido")

        conn.commit()
        print("✅ Stripe webhook OK – servizi attivati")

    except Exception as e:
        conn.rollback()
        print("❌ ERRORE STRIPE:", e)

    finally:
        try:
            conn.close()
        except:
            pass


def attiva_servizio_by_id(conn, servizio_id, **kwargs):
    row = conn.execute(
        "SELECT codice FROM servizi WHERE id = ?",
        (servizio_id,)
    ).fetchone()

    if not row:
        print("Servizio non trovato:", servizio_id)
        return False

    return attiva_servizio(
        codice_servizio=row["codice"],
        **kwargs
    )


def attiva_servizio_da_piano(conn, piano_id, annuncio_id, utente_id, acquisto_id, metodo="admin", importo=0.0, valuta="EUR", riferimento_esterno=None):
    """
    Versione generica (non solo Stripe): attiva un singolo servizio da un piano
    e registra lo storico in acquisti_servizi secondo lo schema reale.
    """
    cur = get_cursor(conn)

    cur.execute(sql("""
        SELECT servizio_id, durata_giorni
        FROM servizi_piani
        WHERE id = ?
    """), (piano_id,))
    piano = cur.fetchone()

    if not piano:
        return

    servizio_id = int(piano["servizio_id"])

    # ✅ storico acquisto servizio (schema reale)
    cur.execute(sql("""
        INSERT INTO acquisti_servizi
        (utente_id, servizio_id, metodo, importo, valuta, riferimento_esterno)
        VALUES (?, ?, ?, ?, ?, ?)
    """), (int(utente_id), servizio_id, metodo, float(importo), (valuta or "EUR").upper(), riferimento_esterno))

    # ✅ attiva
    attiva_servizio(
        conn=conn,
        servizio_id=servizio_id,
        annuncio_id=annuncio_id,
        utente_id=utente_id,
        durata_giorni=piano["durata_giorni"],
        acquisto_id=acquisto_id,
        attivato_da=metodo
    )


def attiva_pacchetto_da_piano(conn, piano_id, annuncio_id, utente_id, acquisto_id, metodo="admin", importo_totale=0.0, valuta="EUR", riferimento_esterno=None):
    """
    Versione generica (non solo Stripe): attiva tutti i servizi del pacchetto
    e registra lo storico in acquisti_servizi secondo lo schema reale.
    """
    cur = get_cursor(conn)

    cur.execute(sql("""
        SELECT
            ps.servizio_id,
            COALESCE(ps.durata_override, sp.durata_giorni) AS durata_finale
        FROM pacchetti_servizi ps
        JOIN servizi_piani sp
          ON sp.servizio_id = ps.servizio_id
        WHERE ps.pacchetto_id = (
            SELECT pacchetto_id
            FROM pacchetti_piani
            WHERE id = ?
        )
    """), (piano_id,))

    servizi = cur.fetchall()
    if not servizi:
        return

    quota = float(importo_totale) / float(len(servizi)) if len(servizi) > 0 else 0.0

    for s in servizi:
        servizio_id = int(s["servizio_id"])

        # ✅ storico acquisto servizio (schema reale)
        cur.execute(sql("""
            INSERT INTO acquisti_servizi
            (utente_id, servizio_id, metodo, importo, valuta, riferimento_esterno)
            VALUES (?, ?, ?, ?, ?, ?)
        """), (int(utente_id), servizio_id, metodo, quota, (valuta or "EUR").upper(), riferimento_esterno))

        # ✅ attiva
        attiva_servizio(
            conn=conn,
            servizio_id=servizio_id,
            annuncio_id=annuncio_id,
            utente_id=utente_id,
            durata_giorni=s["durata_finale"],
            acquisto_id=acquisto_id,
            attivato_da=metodo
        )

# --- Modifica Profilo Utente ---
@app.route('/utente/modifica', methods=['GET', 'POST'])
@login_required
def modifica_profilo():
    conn = get_db_connection()
    c = get_cursor(conn)

    if request.method == 'POST':
        nome = request.form['nome'].strip()
        cognome = request.form['cognome'].strip()
        citta = request.form['citta'].strip()
        username = request.form['username'].strip()
        nuova_password = request.form.get('nuova_password', '').strip()
        conferma_password = request.form.get('conferma_password', '').strip()

        # 🔹 Controlla che lo username non sia già usato da altri
        c.execute(sql("SELECT id FROM utenti WHERE username = ? AND id != ?"), (username, g.utente['id']))
        altro = c.fetchone()
        if altro:
            flash("Questo username è già in uso. Scegline un altro.")

            return redirect(url_for('modifica_profilo'))

        # 🔹 Gestione cambio password (facoltativo)
        if nuova_password:
            if nuova_password != conferma_password:
                flash("Le password non coincidono.")

                return redirect(url_for('modifica_profilo'))
            hashed_pw = generate_password_hash(nuova_password)
            c.execute(
                "UPDATE utenti SET nome = ?, cognome = ?, citta = ?, username = ?, password = ? WHERE id = ?",
                (nome, cognome, citta, username, hashed_pw, g.utente['id'])
            )
        else:
            c.execute(
                "UPDATE utenti SET nome = ?, cognome = ?, citta = ?, username = ? WHERE id = ?",
                (nome, cognome, citta, username, g.utente['id'])
            )

        conn.commit()

        # 🔹 Aggiorna la sessione con i nuovi dati dell'utente
        session['utente_username'] = username
        session.modified = True


        flash("Profilo aggiornato con successo.")
        return redirect(url_for('dashboard'))

    # GET → mostra dati correnti
    cur = get_cursor(conn)
    cur.execute(sql("SELECT * FROM utenti WHERE id = ?"), (g.utente['id'],))
    utente = cur.fetchone()

    return render_template('modifica_profilo.html', utente=utente)

# ---------------------------
# IMPOSTAZIONI → PROFILO
# ---------------------------

@app.route("/impostazioni")
@login_required
def impostazioni():
    if not session.get("utente_id"):
        return redirect(url_for("login"))
    return render_template("impostazioni.html")


@app.route("/impostazioni/modifica-username", methods=["GET", "POST"])
@login_required
def modifica_username():
    if request.method == "POST":
        nuovo = request.form.get("username", "").strip().upper()   # ✅ SALVA MAIUSCOLO

        if nuovo:
            conn = get_db_connection()
            cur = get_cursor(conn)

            # ✅ controllo duplicati case-insensitive
            cur.execute(sql("SELECT id FROM utenti WHERE UPPER(username)=?"), (nuovo,))
            esistente = cur.fetchone()

            if esistente and esistente[0] != session["utente_id"]:
                flash("Questo ID utente è già stato scelto.", "error")

                return redirect(url_for("modifica_username"))

            cur.execute(
                "UPDATE utenti SET username=? WHERE id=?",
                (nuovo, session["utente_id"])
            )
            conn.commit()


            # ✅ aggiorna sessione
            session['utente_username'] = nuovo
            session.modified = True

            flash("Username aggiornato", "success")
            return redirect(url_for("impostazioni"))

    return render_template("forms/modifica_username.html")

@app.route("/impostazioni/modifica-password", methods=["GET", "POST"])
@login_required
def modifica_password():
    if request.method == "POST":
        pw_attuale = request.form.get("password_attuale", "")
        nuova_pw = request.form.get("nuova_password", "")
        conferma_pw = request.form.get("conferma_password", "")

        if not nuova_pw or nuova_pw != conferma_pw:
            flash("Le nuove password non coincidono.", "error")
            return redirect(url_for('modifica_password'))

        if len(nuova_pw) < 8:
            flash("La password deve avere almeno 8 caratteri.", "error")
            return redirect(url_for("modifica_password"))

        conn = get_db_connection()

        cur = get_cursor(conn)
        cur.execute(sql("SELECT * FROM utenti WHERE id = ?"), (session["utente_id"],))
        utente = cur.fetchone()

        if not utente:

            flash("Utente non trovato.", "error")
            return redirect(url_for("login"))

        # 🔹 Verifica password attuale
        if not check_password_hash(utente["password"], pw_attuale):

            flash("La password attuale non è corretta.", "error")
            return redirect(url_for("modifica_password"))

        # 🔹 Aggiorna SOLO l'hash della password
        hash_pw = generate_password_hash(nuova_pw)
        cur.execute(sql("UPDATE utenti SET password = ? WHERE id = ?"), (hash_pw, session["utente_id"]))
        conn.commit()


        flash("Password aggiornata con successo!", "success")
        return redirect(url_for("impostazioni"))

    return render_template("forms/modifica_password.html")


@app.route("/impostazioni/elimina-account")
@login_required
def elimina_account_step1():
    return render_template("impostazioni/elimina_account_step1.html")


@app.route("/impostazioni/sospendi-account", methods=["POST"])
@login_required
def sospendi_account():
    conn = get_db_connection()

    cur = get_cursor(conn)

    # Aggiorna DB
    cur.execute(sql("UPDATE utenti SET sospeso=1 WHERE id=?"), (session["utente_id"],))
    conn.commit()

    # Recupera email e nome per invio notifica
    utente = cur.execute(
        "SELECT email, nome FROM utenti WHERE id=?",
        (session["utente_id"],)
    ).fetchone()



    # Invia email
    invia_email_sospensione(utente["email"], utente["nome"])

    # Flag per messaggio logout
    session["sospensione_logout"] = True

    # Logout automatico
    return redirect(url_for("logout"))


@app.route("/impostazioni/elimina-account/confirm", methods=["GET", "POST"])
@login_required
def elimina_account_step2():
    if request.method == "POST":
        conn = get_db_connection()
        cur = get_cursor(conn)

        cur.execute(sql("DELETE FROM utenti WHERE id=?"), (session["utente_id"],))
        conn.commit()

        session.clear()
        flash("Account eliminato definitivamente.", "success")
        return redirect(url_for("home"))

    return render_template("impostazioni/elimina_account_step2.html")


@app.route("/impostazioni/riattivazione-account")
@login_required
def riattivazione_account():
    if not session.get("sospeso"):
        return redirect(url_for("dashboard"))

    return render_template("impostazioni/riattiva_account.html")


@app.route("/impostazioni/riattiva-account", methods=["POST"])
@login_required
def riattiva_account():
    conn = get_db_connection()
    cur = get_cursor(conn)

    cur.execute(sql("UPDATE utenti SET sospeso=0 WHERE id=?"), (session["utente_id"],))
    conn.commit()

    # rimuove flag sospeso
    session.pop("sospeso", None)

    flash("Account riattivato! Per motivi di sicurezza effettua di nuovo il login.", "success")
    return redirect(url_for("login"))

# ----------------------------------------
# 🔒 CONTROLLO SOSPENSIONE AUTOMATICO
# ----------------------------------------
@app.before_request
def controllo_sospensione():

    rotte_escluse = [
        'login', 'logout', 'riattivazione_account', 'riattiva_account',
        'static'
    ]

    # Evita loop: non controllare per queste rotte
    if request.endpoint is None or request.endpoint in rotte_escluse:
        return

    # Se non è loggato: ignora
    if not session.get("utente_id"):
        return

    # Controlla stato nel DB
    conn = get_db_connection()

    c = get_cursor(conn)
    c.execute(sql("SELECT sospeso, disattivato_admin FROM utenti WHERE id=?"), (session["utente_id"],))
    stato = c.fetchone()


    # 🔒 Utente sospeso → attiva pagina riattivazione
    if stato and stato["sospeso"] == 1:
        session["sospeso"] = True
        return redirect(url_for("riattivazione_account"))

    # 🚫 Account disattivato dall’admin → blocco totale
    if stato and stato["disattivato_admin"] == 1:
        session.clear()
        flash("Il tuo account è stato disattivato dall’amministrazione.", "error")
        return redirect(url_for("login"))

# ---------------------------
# IMPOSTAZIONI → SICUREZZA
# ---------------------------

@app.route("/impostazioni/notifiche-email", methods=["GET", "POST"])
@login_required
def email_notifiche():
    if request.method == "POST":
        attivo = 1 if request.form.get("email_notifiche") == "on" else 0
        conn = get_db_connection()
        cur = get_cursor(conn)
        cur.execute(sql("UPDATE utenti SET email_notifiche=? WHERE id=?"), (attivo, session["utente_id"]))
        conn.commit()
        flash("Preferenze aggiornate", "success")
        return redirect(url_for("impostazioni"))
    return render_template("forms/email_notifiche.html")


# ---------------------------
# IMPOSTAZIONI → FOTO PROFILO
# ---------------------------

@app.route("/impostazioni/cambia-foto", methods=["GET", "POST"])
@login_required
def cambia_foto():
    if request.method == "POST":
        file = request.files.get("foto")

        if not file or file.filename == "":
            flash("Carica una foto valida.", "error")
            return redirect(url_for("cambia_foto"))

        upload_dir = os.path.join("static", "uploads", "profile")
        os.makedirs(upload_dir, exist_ok=True)

        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)

        # SALVA IL PERCORSO COERENTE
        percorso_db = f"uploads/profile/{filename}"

        conn = get_db_connection()
        cur = get_cursor(conn)
        cur.execute(sql("""
            UPDATE utenti SET foto_profilo=? WHERE id=?
        """), (percorso_db, session["utente_id"]))
        conn.commit()


        flash("Foto profilo aggiornata con successo!", "success")
        return redirect(url_for("impostazioni"))

    return render_template("forms/cambia_foto.html")


@app.route("/impostazioni/cambia-copertina", methods=["GET", "POST"])
@login_required
def cambia_copertina():
    if request.method == "POST":
        file = request.files.get("copertina")

        if not file or file.filename == "":
            flash("Carica una copertina valida.", "error")
            return redirect(url_for("cambia_copertina"))

        upload_dir = os.path.join("static", "uploads", "profili", "copertine")
        os.makedirs(upload_dir, exist_ok=True)

        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)

        percorso_db = f"uploads/profili/copertine/{filename}"

        conn = get_db_connection()
        cur = get_cursor(conn)
        cur.execute(sql("""
            UPDATE utenti SET copertina=? WHERE id=?
        """), (percorso_db, session["utente_id"]))
        conn.commit()


        flash("Copertina aggiornata con successo!", "success")
        return redirect(url_for("impostazioni"))

    return render_template("forms/cambia_copertina.html")

#NUOVO Annuncio

@app.route("/nuovo-annuncio", methods=["GET", "POST"])
@login_required
@foto_obbligatoria
def nuovo_annuncio():
    if "utente_id" not in session:
        flash("Devi essere loggato per creare un annuncio.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()

    c = get_cursor(conn)

    # ✅ Verifica che l’utente sia attivo
    c.execute(
        "SELECT * FROM utenti WHERE id = ?",
        (session["utente_id"],)
    )
    utente = c.fetchone()

    if not utente or utente["attivo"] != 1:

        flash("Il tuo account deve essere approvato per pubblicare annunci.", "warning")
        return redirect(url_for("dashboard"))

    # ✅ Carica filtri categoria
    with open("static/data/filtri_categoria.json", "r", encoding="utf-8") as f:
        filtri_per_categoria = json.load(f)

    # =========================================================
    # 📤 POST
    # =========================================================
    if request.method == "POST":

        # 🔹 CAMPI BASE
        categoria_raw = request.form.get("categoria", "")
        categoria = to_slug(categoria_raw)
        tipo_annuncio = request.form.get("tipo_annuncio", "").strip().lower()
        titolo = request.form.get("titolo", "").strip()
        descrizione = request.form.get("descrizione", "").strip()

        if not categoria:

            flash("Seleziona una categoria.", "warning")
            return redirect(url_for("nuovo_annuncio"))

        if not titolo:

            flash("Inserisci un titolo per l’annuncio.", "warning")
            return redirect(url_for("nuovo_annuncio"))

        if not descrizione:

            flash("Inserisci una descrizione dettagliata.", "warning")
            return redirect(url_for("nuovo_annuncio"))

        # 🔹 ZONA + PROVINCIA
        zona = request.form.get("zona", "").strip()
        provincia = request.form.get("provincia", "").strip() or None

        # 🔹 ALTRI CAMPI
        filtri = request.form.getlist("filtri_categoria")
        bio = request.form.get("bio_utente", "").strip()
        prezzo = request.form.get("prezzo", "").strip()
        telefono = request.form.get("telefono", "").strip()
        email = request.form.get("email", "").strip()
        username_modificato = request.form.get("username", utente["username"])

        # =====================================================
        # 🛡️ VALIDAZIONI
        # =====================================================

        if tipo_annuncio not in ("offro", "cerco"):

            flash("Devi selezionare se l’annuncio è 'Offro' oppure 'Cerco'.", "warning")
            return redirect(url_for("nuovo_annuncio"))

        if not zona:

            flash("Seleziona una zona o un comune dall’elenco.", "warning")
            return redirect(url_for("nuovo_annuncio"))

        # 🔒 1 annuncio per categoria per utente
        c.execute(sql("""
            SELECT id
            FROM annunci
            WHERE utente_id = ?
              AND categoria = ?
              AND stato IN ('in_attesa', 'approvato')
            LIMIT 1
        """), (utente["id"], categoria))

        esiste = c.fetchone()

        if esiste:

            flash(
                "Hai già un annuncio in questa categoria (in attesa o approvato). "
                "Per pubblicarne un altro, elimina o modifica quello esistente.",
                "warning"
            )
            return redirect(url_for("dashboard"))

        # =====================================================
        # 📸 UPLOAD MEDIA
        # =====================================================
        media_files = request.files.getlist("media")
        media_paths = []
        upload_dir = os.path.join("static", "uploads", "annunci")
        os.makedirs(upload_dir, exist_ok=True)

        for file in media_files:
            if file and file.filename:
                filename = f"{uuid.uuid4().hex}_{file.filename}"
                file.save(os.path.join(upload_dir, filename))
                media_paths.append(f"uploads/annunci/{filename}")

        # =====================================================
        # 💾 INSERT DB
        # =====================================================
        c.execute(sql("""
            INSERT INTO annunci (
                utente_id,
                username,
                categoria,
                tipo_annuncio,
                titolo,
                descrizione,
                bio_utente,
                zona,
                provincia,
                filtri_categoria,
                media,
                prezzo,
                telefono,
                email,
                stato
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'in_attesa')
        """), (
            utente["id"],
            username_modificato,
            categoria,
            tipo_annuncio,
            titolo,
            descrizione,
            bio,
            zona,
            provincia,
            ",".join(filtri),
            ",".join(media_paths),
            prezzo,
            telefono,
            email
        ))

        conn.commit()


        # 👁️ Visibilità pubblica automatica
        conn = get_db_connection()
        conn.execute(
            "UPDATE utenti SET visibile_pubblicamente = 1 WHERE id = ?",
            (utente["id"],)
        )
        conn.commit()


        # 🔔 Aggiorna contatori admin
        invalidate_admin_counters()

        flash(
            "✅ Annuncio creato! Sarà pubblicato dopo approvazione dell’amministratore.",
            "success"
        )
        return redirect(url_for("dashboard"))

    # =========================================================
    # 📥 GET
    # =========================================================

    return render_template(
        "nuovo_annuncio.html",
        username=utente["username"],
        filtri_per_categoria=filtri_per_categoria
    )

@app.context_processor
def inject_servizi_utils():
    return dict(
        servizio_attivo_per_annuncio=servizio_attivo_per_annuncio,
        servizio_attivo_per_utente=servizio_attivo_per_utente
    )

@app.route("/annuncio/<int:id>")
def visualizza_annuncio_pubblico(id):
    conn = get_db_connection()

    c = get_cursor(conn)

    # 🔹 SQL condivisa: AFFIDABILITÀ TOP (identica a /cerca)
    affidabilita_top_sql = """
        CASE
          -- 🟢 OVERRIDE ADMIN
          WHEN EXISTS (
            SELECT 1
            FROM attivazioni_servizi act
            JOIN servizi s ON s.id = act.servizio_id
            WHERE s.codice = 'badge_affidabilita'
              AND act.utente_id = a.utente_id
              AND act.stato = 'attivo'
          ) THEN 1

          -- ⭐ REGOLA AUTOMATICA
          WHEN
            COALESCE((
              SELECT AVG(r.voto)
              FROM recensioni r
              WHERE r.id_destinatario = a.utente_id
                AND r.stato = 'approvato'
            ), 0) >= 4.2
          AND
            COALESCE((
              SELECT COUNT(*)
              FROM recensioni r
              WHERE r.id_destinatario = a.utente_id
                AND r.stato = 'approvato'
            ), 0) >= 5
          THEN 1

          ELSE 0
        END AS affidabilita_top
    """

    # 🔹 Query annuncio pubblico
    c.execute(sql(f"""
        SELECT
            a.*,
            a.tipo_annuncio,

            u.username,
            u.nome,
            u.cognome,
            u.email AS email,
            u.telefono AS telefono,
            u.foto_profilo,

            {affidabilita_top_sql},

            -- ⭐ MEDIA RECENSIONI
            COALESCE(ROUND((
                SELECT AVG(r.voto)
                FROM recensioni r
                WHERE r.id_destinatario = a.utente_id
                  AND r.stato = 'approvato'
            ), 1), 0) AS media_recensioni,

            -- 🔢 NUMERO RECENSIONI
            COALESCE((
                SELECT COUNT(*)
                FROM recensioni r
                WHERE r.id_destinatario = a.utente_id
                  AND r.stato = 'approvato'
            ), 0) AS numero_recensioni

        FROM annunci a
        JOIN utenti u ON a.utente_id = u.id
        WHERE a.id = ?
          AND u.attivo = 1
          AND u.sospeso = 0
          AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
          AND (u.ruolo IS NULL OR u.ruolo != 'admin')
    """), (id,))

    row = c.fetchone()


    # ❌ Annuncio non trovato
    if not row:
        return "Annuncio non trovato", 404

    annuncio = dict(row)
    annuncio["tipo_annuncio"] = (annuncio.get("tipo_annuncio") or "").lower()

    # 🔒 Annuncio non approvato → visibile solo al proprietario
    if annuncio["stato"] != "approvato":
        if not g.utente or g.utente["id"] != annuncio["utente_id"]:
            return "Annuncio non ancora pubblicato.", 403

    # ✅ SERVIZI — COME IN DASHBOARD
    contatti_attivi = servizio_attivo_per_utente(
        utente_id=annuncio["utente_id"],
        codice_servizio="contatti"
    )

    # 🔁 Gestione intelligente del tasto “Torna”
    ref = request.referrer or ""

    if "/modifica" in ref and session.get("last_annuncio_origin"):
        back_url = session["last_annuncio_origin"]
    else:
        if ref and "/modifica" not in ref:
            session["last_annuncio_origin"] = ref
        back_url = ref or session.get("last_annuncio_origin") or url_for("home")

    return render_template(
        "annuncio_pubblico.html",
        annuncio=annuncio,
        contatti_attivi=contatti_attivi,
        back_url=back_url
    )

    # --- Profilo pubblico dell’operatore ---
@app.route("/profilo_operatore/<int:id>")
def profilo_operatore(id):
    conn = get_db_connection()

    c = get_cursor(conn)

    c.execute(sql("SELECT * FROM operatori WHERE id = ?"), (id,))
    operatore = c.fetchone()


    if not operatore:
        return "Operatore non trovato", 404

    return render_template("profilo_operatore.html", operatore=operatore)

from services import servizio_attivo_per_utente

@app.route("/profilo/<int:id>")
def profilo_pubblico(id):
    """Visualizza il profilo pubblico completo di un utente (stile Facebook)."""
    conn = get_db_connection()

    c = get_cursor(conn)

    # 🔹 Carica dati utente
    c.execute(sql("""
        SELECT id, nome, cognome, email, username, citta, lingue, frase,
               telefono, email_pubblica, indirizzo_studio,
               sito_web, instagram, facebook, linkedin,
               orari, preferenze_contatto,
               visibile_pubblicamente, visibile_in_chat,
               media_recensioni, numero_recensioni,
               foto_profilo, copertina, foto_galleria,
               offro_1, offro_2, offro_3, offro_4, offro_5, offro_6, offro_7, offro_8,
               cerco_1, cerco_2, cerco_3, cerco_4, cerco_5, cerco_6, cerco_7, cerco_8,
               esperienza_1, esperienza_2, esperienza_3,
               studio_1, studio_2, studio_3,
               certificazioni, descrizione
        FROM utenti
        WHERE id = ?
          AND sospeso = 0
          AND (disattivato_admin IS NULL OR disattivato_admin = 0)
          AND attivo = 1
          AND (ruolo IS NULL OR ruolo != 'admin')
    """), (id,))
    utente = c.fetchone()

    if not utente:

        flash("Profilo non trovato.", "error")
        return redirect(url_for("cerca"))

    utente = dict(utente)

    # 🧹 Normalizza None → ""
    for k, v in utente.items():
        if v is None:
            utente[k] = ""

    # 🔒 Controllo visibilità profilo
    if not bool(utente.get("visibile_pubblicamente", 0)):
        if not g.utente or g.utente["id"] != utente["id"]:

            flash("Questo profilo è privato.", "info")
            return redirect(url_for("cerca"))

    # =========================================================
    # 🔑 CONTROLLO SERVIZIO CONTATTI (PUNTO CHIAVE)
    # =========================================================
    servizio_contatti_attivo = servizio_attivo_per_utente(
        utente_id=utente["id"],
        codice_servizio="contatti"
    )

    # 🔹 Recensioni
    recensioni = get_recensioni_utente(id)
    media, totale = calcola_media_recensioni(id)

    # 🔹 Annunci
    c.execute(sql("""
        SELECT id, titolo, categoria, zona, prezzo, descrizione,
               media AS media_img, data_pubblicazione, filtri_categoria
        FROM annunci
        WHERE utente_id = ? AND stato = 'approvato'
        ORDER BY data_pubblicazione DESC
    """), (id,))
    annunci = [dict(r) for r in c.fetchall()]


    # =========================================================
    # 🔹 OFFRO / CERCO
    # =========================================================
    categorie = [
        "Operatori benessere",
        "Aiuto in casa",
        "Ripetizioni",
        "Pet-sitter",
        "Caregiver",
        "Gite / Compagni di allenamento",
        "Biglietti spettacoli",
        "Libri scuola"
    ]

    offro_presenti = []
    cerco_presenti = []

    for i in range(1, 9):
        try:
            utente[f"offro_{i}"] = int(utente.get(f"offro_{i}") or 0)
            utente[f"cerco_{i}"] = int(utente.get(f"cerco_{i}") or 0)
        except Exception:
            utente[f"offro_{i}"] = 0
            utente[f"cerco_{i}"] = 0

    for i, cat in enumerate(categorie, start=1):
        if utente[f"offro_{i}"] == 1:
            offro_presenti.append(cat)
        if utente[f"cerco_{i}"] == 1:
            cerco_presenti.append(cat)

    # =========================================================
    # ✅ RENDER
    # =========================================================
    return render_template(
        "dashboard.html",
        utente=utente,
        annunci=annunci,
        pubblico=True,
        media_recensioni=media,
        totale_recensioni=totale,
        offro_presenti=offro_presenti,
        cerco_presenti=cerco_presenti,
        servizio_contatti_attivo=servizio_contatti_attivo,
        page="profilo"
    )

@app.route("/utente/toggle_visibilita", methods=["POST"])
@login_required
def toggle_visibilita():
    conn = get_db_connection()
    c = get_cursor(conn)

    # Leggi stato attuale
    c.execute(sql("SELECT visibile_pubblicamente FROM utenti WHERE id = ?"), (g.utente["id"],))
    row = c.fetchone()
    if not row:

        flash("Utente non trovato.", "error")
        return redirect(url_for("dashboard"))

    stato_attuale = row["visibile_pubblicamente"]

    # Se vuole passare da visibile → invisibile, controlla che non abbia annunci attivi
    if stato_attuale == 1:
        c.execute(sql("""
            SELECT COUNT(*) FROM annunci
            WHERE utente_id = ? AND stato = 'approvato'
        """), (g.utente["id"],))
        annunci_attivi = fetchone_value(c.fetchone())

        if annunci_attivi > 0:

            flash("⚠️ Non puoi rendere invisibile il profilo mentre hai annunci pubblicati. "
                  "Archivia o elimina prima gli annunci approvati.", "warning")
            return redirect(request.referrer or url_for("dashboard"))

    # Alterna stato
    nuovo_stato = 0 if stato_attuale == 1 else 1
    c.execute(sql("UPDATE utenti SET visibile_pubblicamente = ? WHERE id = ?"), (nuovo_stato, g.utente["id"]))
    conn.commit()


    if nuovo_stato == 1:
        flash("✅ Il tuo profilo è ora visibile pubblicamente.", "success")
    else:
        flash("👁️‍🗨️ Il tuo profilo è ora nascosto dai risultati pubblici.", "info")

    return redirect(request.referrer or url_for("dashboard"))

@app.route("/ricerca-utenti")
def ricerca_utenti():
    conn = get_db_connection()
    c = get_cursor(conn)

    raw_nome = (request.args.get("username") or request.args.get("nome") or "").strip()
    zona = (request.args.get("zona") or "").strip()
    raw_cat = (request.args.get("categoria") or "").strip()

    # 👉 normalizzo categoria a slug
    cat_slug = to_slug(raw_cat)
    cat_index = CATEGORIA_TO_INDEX.get(cat_slug)

    print("DEBUG /ricerca-utenti →", {
        "raw_nome": raw_nome,
        "zona": zona,
        "raw_cat": raw_cat,
        "cat_slug": cat_slug,
        "cat_index": cat_index
    })

    query = """
        SELECT
            u.id, u.username, u.nome, u.cognome, u.citta, u.foto_profilo,
            u.visibile_pubblicamente,
            COALESCE(ROUND(AVG(r.voto), 1), 0) AS media_recensioni,
            COUNT(r.id) AS numero_recensioni
        FROM utenti u
        LEFT JOIN recensioni r
               ON r.id_destinatario = u.id AND r.stato = 'approvato'
        WHERE (u.visibile_pubblicamente = 1
               OR (u.visibile_in_chat = 1 AND u.id IN (
                   SELECT DISTINCT CASE
                       WHEN mittente_id = ? THEN destinatario_id
                       WHEN destinatario_id = ? THEN mittente_id
                   END
                   FROM messaggi_chat
                   WHERE mittente_id = ? OR destinatario_id = ?
               )))
          AND u.sospeso = 0
          AND (u.disattivato_admin IS NULL OR u.disattivato_admin = 0)
          AND u.attivo = 1
          AND u.foto_profilo IS NOT NULL
          AND u.foto_profilo != ''
          AND (u.ruolo IS NULL OR u.ruolo != 'admin')
    """

    params = [session.get("utente_id")] * 4

    # 🔍 filtro nome / username
    if raw_nome:
        like = f"%{raw_nome.lower()}%"
        query += """
            AND (
                LOWER(u.username) LIKE ?
                OR LOWER(u.nome) LIKE ?
                OR LOWER(u.cognome) LIKE ?
            )
        """
        params.extend([like, like, like])

    # 📍 filtro zona
    if zona:
        query += " AND LOWER(u.citta) LIKE ?"
        params.append(f"%{zona.lower()}%")

    # ✅ filtro categoria CORRETTO (offro_X / cerco_X)
    if cat_index:
        query += f"""
            AND (
                u.offro_{cat_index} = 1
                OR u.cerco_{cat_index} = 1
            )
        """

    query += " GROUP BY u.id ORDER BY media_recensioni DESC"

    c.execute(sql(query), params)
    utenti = c.fetchall()


    logged_in = "utente_id" in session

    return render_template(
        "ricerca_utenti.html",
        utenti=utenti,
        logged_in=logged_in,
        nome=raw_nome,
        zona=zona,
        categoria=cat_slug,
        CATEGORY_MAP=CATEGORY_MAP
    )

# ==========================================================
# 6️⃣ CHAT TRA UTENTI
# ==========================================================
@app.route("/chat")
@login_required
def chat_threads_view():
    """Mostra tutte le chat dell’utente loggato"""
    threads = chat_threads(g.utente["id"])
    return render_template(
        "chat_threads.html",
        threads=threads,
        utente=g.utente,
        my_id=g.utente["id"]  # 👈 così il template sa qual è il mio id
    )

@app.route("/chat/threads_json")
@login_required
def chat_threads_json():
    """Restituisce i thread chat aggiornati in formato JSON per aggiornamenti live."""
    rows = chat_threads(g.utente["id"])   # 👈 come avevi prima
    threads = []

    for t in rows:
        d = dict(t)

        # 🔒 Se l'altro utente è l'admin → maschera i dati
        if is_admin(d.get("other_id")):
            d["other_nome"] = "MyLocalCare • Supporto"
            d["other_username"] = "support"
            d["other_foto"] = "img/support.png"

        threads.append(d)

    return jsonify(threads)

@app.route("/chat/<int:other_id>/json")
@login_required
def chat_conversazione_json(other_id):
    """Restituisce i messaggi della chat in formato JSON (per aggiornamenti live)."""
    user_id = g.utente["id"]
    after_id = request.args.get("after_id", type=int)

    # 🔹 Messaggi
    messaggi = chat_conversazione(user_id, other_id, after_id=after_id)
    chat_segna_letti(user_id, other_id)
    socketio.emit('update_unread_count', {'for_user': user_id}, room=f"user_{user_id}")

    # 🔹 Recupero info "altro utente" per nome/avatar
    conn = get_db_connection()

    c = get_cursor(conn)
    c.execute(sql("""
        SELECT id, nome, cognome, username, foto_profilo
        FROM utenti
        WHERE id = ?
    """), (other_id,))
    altro = c.fetchone()


    # 🔒 Maschera admin
    if altro and is_admin(altro["id"]):
        other_display_name = "MyLocalCare • Supporto"
        other_avatar = "img/support.png"
    elif altro:
        other_display_name = f"{altro['nome']} {altro['cognome']}"
        other_avatar = altro["foto_profilo"]
    else:
        other_display_name = ""
        other_avatar = None

    def get_val(m, *keys):
        for k in keys:
            if k in m.keys():
                return m[k]
        return ""

    return jsonify({
        "ok": True,
        "me_id": user_id,
        "other_display_name": other_display_name,  # 👈 AGGIUNTO
        "other_avatar": other_avatar,              # 👈 AGGIUNTO
        "messages": [
            {
                "id": m["id"],
                "mittente_id": m["mittente_id"],
                "destinatario_id": m["destinatario_id"],
                "testo": m["testo"],
                "created_at": m["created_at"],
                "consegnato": m["consegnato"],
                "letto": m["letto"]
            }
            for m in messaggi
        ],
        "typing": typing_state.get((other_id, user_id), False)
    })

@app.route("/chat/unread_count")
@login_required
def chat_unread_count():
    """Ritorna il numero totale di messaggi non letti per l’utente loggato."""
    from models import count_chat_non_letti
    return jsonify({"count": count_chat_non_letti(g.utente["id"])})

@app.route("/chat/<int:other_id>")
@login_required
@foto_obbligatoria
def chat_conversazione_view(other_id):
    """Mostra la pagina della chat tra l’utente loggato e un altro utente."""
    conn = get_db_connection()

    c = get_cursor(conn)

    # 🔹 Recupera l’altro utente (solo se non sospeso / non disattivato)
    c.execute(sql("""
        SELECT id, nome, cognome, username, foto_profilo
        FROM utenti
        WHERE id = ?
          AND sospeso = 0
          AND (disattivato_admin IS NULL OR disattivato_admin = 0)
          AND attivo = 1
    """), (other_id,))
    altro = c.fetchone()
    if not altro:

        return "Utente non disponibile", 404

    # 🔒 Maschera l'admin verso gli altri utenti
    if is_admin(altro["id"]):
        altro = dict(altro)
        altro["nome"] = "MyLocalCare"
        altro["cognome"] = "Supporto"
        altro["username"] = "support"
        altro["foto_profilo"] = "img/support.png"

    # 🔹 Recupera i messaggi esistenti
    messaggi = chat_conversazione(g.utente["id"], other_id)


    # 🔹 Segna come letti i messaggi ricevuti
    chat_segna_letti(g.utente["id"], other_id)
    socketio.emit('update_unread_count', {'for_user': g.utente["id"]}, room=f"user_{g.utente['id']}")

    return render_template(
        "chat_conversazione.html",
        altro=altro,
        conversazione=messaggi,
        utente=g.utente,
        is_support=is_admin(other_id)
    )

typing_state = {}

@app.route("/chat/<int:other_id>/chiudi", methods=["POST"])
@admin_required
def chiudi_chat(other_id):
    admin_id = g.utente["id"]

    conn = get_db_connection()

    conn.execute(sql(f"""
        INSERT INTO chat_chiusure (admin_id, user_id, closed_at)
        VALUES (?, ?, {now_sql()})
    """), (admin_id, other_id))

    conn.commit()


    flash("Chat chiusa correttamente.", "success")
    return redirect(url_for("utente_messaggi"))

@app.route("/video/start", methods=["POST"])
@login_required
def video_start():

    data = request.get_json()
    altro_id = data.get("altro_utente_id")

    if not altro_id:
        return jsonify({"error": "Utente non valido"}), 400

    from datetime import datetime
    import time
    import requests


    conn = get_db_connection()
    cur = get_cursor(conn)

    # 🚫 BLOCCO SE UTENTE GIÀ IN CHIAMATA ATTIVA (con timeout 60s)
    cur.execute(sql("""
        SELECT id
        FROM video_call_log
        WHERE in_corso = 1
          AND (utente_1 = ? OR utente_2 = ?)
          AND last_ping IS NOT NULL
          AND last_ping >= CURRENT_TIMESTAMP - INTERVAL '60 seconds'
        LIMIT 1
    """), (g.utente["id"], g.utente["id"]))

    call_in_corso = cur.fetchone()

    if call_in_corso:
        cur.close()
        return jsonify({
            "error": "Sei già in una videochiamata in corso."
        }), 409

    # 🔹 Recupero utenti
    me = cur.execute(
        "SELECT maggiorenne_verificato FROM utenti WHERE id = ?",
        (g.utente["id"],)
    ).fetchone()

    altro = cur.execute(
        "SELECT maggiorenne_verificato FROM utenti WHERE id = ?",
        (altro_id,)
    ).fetchone()

    if not altro:
        cur.close()
        return jsonify({"error": "Utente non trovato"}), 404

    # 🔒 CONTROLLO BUDGET
    mese_corrente = datetime.now().strftime("%Y-%m")

    limite = cur.execute(sql("""
        SELECT bloccato
        FROM video_limiti_mensili
        WHERE mese = ?
    """), (mese_corrente,)).fetchone()

    if limite and limite["bloccato"] == 1:
        cur.close()
        return jsonify({
            "error": "Il servizio video è temporaneamente sospeso per questo mese."
        }), 403

    # 🔞 VERIFICA MAGGIORENNE
    if me["maggiorenne_verificato"] != 1:
        cur.close()
        return jsonify({"need_verifica": True}), 200

    # 🎥 CREAZIONE ROOM
    room_name = f"lc_{g.utente['id']}_{altro_id}_{int(time.time())}"

    headers = {
        "Authorization": f"Bearer {os.getenv('DAILY_API_KEY')}",
        "Content-Type": "application/json"
    }

    payload = {
        "name": room_name,
        "properties": {"max_participants": 2}
    }

    r = requests.post(
        "https://api.daily.co/v1/rooms",
        headers=headers,
        json=payload,
        timeout=5   # 🔥 fondamentale
    )

    if r.status_code != 200:
        cur.close()
        return jsonify({"error": "Errore creazione room Daily"}), 500

    room_url = r.json()["url"]

    # 📝 LOG CHIAMATA
    cur.execute(sql(f"""
        INSERT INTO video_call_log (
            room_name,
            utente_1,
            utente_2,
            in_corso,
            last_ping
        )
        VALUES (?, ?, ?, 1, {now_sql()})
    """), (room_name, g.utente["id"], altro_id))

    conn.commit()
    cur.close()

    # 📞 NOTIFICA CHIAMATA
    socketio.emit(
        "incoming_call",
        {
            "from": g.utente["id"],
            "room_name": room_name,
            "room_url": room_url
        },
        room=f"user_{altro_id}"
    )

    # 🔴 NOTIFICA UTENTE OCCUPATO
    socketio.emit(
        "video_busy",
        {"user_id": g.utente["id"], "busy": True},
        room=f"user_{altro_id}"
    )

    return jsonify({
        "room_name": room_name,
        "room_url": room_url
    })

@app.route("/video/verifica-maggiorenne", methods=["POST"])
@login_required
def verifica_maggiorenne():

    ip = request.remote_addr

    conn = get_db_connection()
    conn.execute(sql(f"""
        UPDATE utenti
        SET maggiorenne_verificato = 1,
            data_verifica_maggiorenne = {now_sql()},
            ip_verifica_maggiorenne = ?,
            versione_consenso = ?
        WHERE id = ?
    """), (ip, "v1.0_video", g.utente["id"]))

    conn.commit()


    return jsonify({"success": True})

@app.route("/video/check-maggiorenne")
@login_required
def video_check_maggiorenne():
    conn = get_db_connection()
    me = conn.execute(
        "SELECT maggiorenne_verificato FROM utenti WHERE id = ?",
        (g.utente["id"],)
    ).fetchone()

    return jsonify({
        "verified": me["maggiorenne_verificato"] == 1
    })

@app.route("/video/end", methods=["POST"])
def video_end():

    room_name = request.json.get("room_name")
    if not room_name:
        return jsonify({"error": "Room non valida"}), 400

    from datetime import datetime, timezone
    conn = get_db_connection()
    cur = get_cursor(conn)

    # 🔒 Prendi SOLO chiamata ancora attiva
    call = cur.execute(sql("""
        SELECT id, created_at
        FROM video_call_log
        WHERE room_name = ?
          AND in_corso = 1
        LIMIT 1
    """), (room_name,)).fetchone()

    if not call:
        return jsonify({"status": "already_closed"})

    # 🔥 created_at ora è datetime vero (TIMESTAMPTZ)
    start_time = call["created_at"]
    end_time = datetime.now(timezone.utc)

    durata_secondi = int((end_time - start_time).total_seconds())

    import math
    participant_minutes = math.ceil((durata_secondi / 60) * 2)

    FREE_MONTHLY = 10000
    COSTO_PER_MINUTO = 0.002

    mese = datetime.now().strftime("%Y-%m")

    used = cur.execute(sql("""
        SELECT minuti_totali
        FROM video_limiti_mensili
        WHERE mese = ?
    """), (mese,)).fetchone()

    used_minutes = used["minuti_totali"] if used else 0

    over_free = max(0, (used_minutes + participant_minutes) - FREE_MONTHLY)
    costo_cent = int(over_free * COSTO_PER_MINUTO * 100)

    # 🔴 CHIUSURA DEFINITIVA
    cur.execute(sql("""
        UPDATE video_call_log
        SET durata_secondi = ?,
            participant_minutes = ?,
            costo_stimato_cent = ?,
            in_corso = 0,
            ended_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """), (durata_secondi, participant_minutes, costo_cent, call["id"]))

    # 📊 UPDATE LIMITE
    cur.execute(sql("""
        INSERT INTO video_limiti_mensili (mese, minuti_totali, costo_totale_cent)
        VALUES (?, ?, ?)
        ON CONFLICT(mese) DO UPDATE SET
            minuti_totali = video_limiti_mensili.minuti_totali + EXCLUDED.minuti_totali,
            costo_totale_cent = video_limiti_mensili.costo_totale_cent + EXCLUDED.costo_totale_cent
    """), (mese, participant_minutes, costo_cent))

    # 🟢 Recupera utenti
    users = cur.execute(sql("""
        SELECT utente_1, utente_2
        FROM video_call_log
        WHERE id = ?
    """), (call["id"],)).fetchone()

    conn.commit()

    # 🟢 Notifica DOPO commit
    if users:
        socketio.emit("video_busy",
            {"user_id": users["utente_1"], "busy": False},
            room=f"user_{users['utente_2']}"
        )
        socketio.emit("video_busy",
            {"user_id": users["utente_2"], "busy": False},
            room=f"user_{users['utente_1']}"
        )

    return jsonify({"status": "ok"})

# ==========================================================
# ❤️ PING CHIAMATA (mantiene viva la call)
# ==========================================================
@app.route("/video/ping", methods=["POST"])
def video_ping():

    room_name = request.json.get("room_name")

    if not room_name:
        return jsonify({"error": "Room non valida"}), 400

    conn = get_db_connection()

    conn.execute(sql(f"""
        UPDATE video_call_log
        SET last_ping = {now_sql()}
        WHERE room_name = ?
        AND in_corso = 1
    """), (room_name,))

    conn.commit()


    return jsonify({"ok": True})

# =====================================================
# 📞 CHIAMATA IN ARRIVO
# =====================================================

@socketio.on("connect")
def handle_connect():
    from flask import session

    user_id = session.get("utente_id")
    if not user_id:
        return

    room = f"user_{user_id}"
    join_room(room)

    print(f"🟢 Socket connesso e utente {user_id} entrato in {room}")

    # 🚀 Avvia cleanup una sola volta
    if not hasattr(app, "video_cleanup_started"):
        app.video_cleanup_started = True
        socketio.start_background_task(cleanup_video_calls)

@socketio.on("video_call_left")
def handle_video_call_left(data):
    from flask import session

    room_name = data.get("room")
    if not room_name:
        return

    user_id = session.get("utente_id")
    if not user_id:
        return

    # manda l'evento a TUTTI tranne chi lo ha inviato
    socketio.emit(
        "video_call_left",
        {"room": room_name},
        skip_sid=request.sid
    )

@socketio.on("video_call_rejected")
def handle_video_call_rejected(data):
    from flask import session

    room_name = data.get("room")
    from_user = data.get("from_user")

    if not room_name or not from_user:
        return

    # invia SOLO al chiamante
    socketio.emit(
        "video_call_rejected",
        {"room": room_name},
        room=f"user_{from_user}"
    )

    # 🔥 Notifica anche la room video (se qualcuno fosse già entrato)
    socketio.emit(
        "force_call_end",
        {"room": room_name},
        room=room_name
    )

# ==========================================================
# 🔴 EVENTI SOCKET.IO — CHAT IN TEMPO REALE
# ==========================================================

@socketio.on('join')
def on_join(data=None):
    from flask import session
    user_id = None
    if data and data.get("user_id"):
        user_id = data["user_id"]
    elif session.get("utente_id"):
        user_id = session.get("utente_id")
    if not user_id:
        return
    room = f"user_{user_id}"
    join_room(room)
    print(f"🔵 Utente {user_id} entrato nella stanza {room}")

@socketio.on("check_video_status")
def check_video_status(data):
    user_id = data.get("user_id")

    conn = None
    try:
        conn = get_db_connection()

        conn.execute(sql("""
            UPDATE video_call_log
            SET in_corso = 0,
                ended_at = CURRENT_TIMESTAMP
            WHERE in_corso = 1
              AND last_ping IS NOT NULL
              AND last_ping < CURRENT_TIMESTAMP - INTERVAL '60 seconds'
        """))
        conn.commit()

        call = conn.execute(sql("""
            SELECT id FROM video_call_log
            WHERE in_corso = 1
            AND (utente_1 = ? OR utente_2 = ?)
            LIMIT 1
        """), (user_id, user_id)).fetchone()

        emit("video_status_result", {
            "busy": bool(call)
        })

    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def clear_recently_read(user_id, delay=None):
    """
    Cancella l'ultima chat letta dopo 'delay' secondi usando eventlet.
    """
    if delay is None:
        delay = app.config.get('CHAT_RECENTLY_READ_TTL', 5)

    socketio.start_background_task(_delayed_clear_recently_read, user_id, delay)


def _delayed_clear_recently_read(user_id, delay):
    # 🔥 Yield cooperativo
    socketio.sleep(delay)

    if 'CHAT_ULTIMA_LETTA' in app.config:
        app.config['CHAT_ULTIMA_LETTA'].pop(user_id, None)
        print(f"🧹 Pulita ultima chat letta per utente {user_id}")

@socketio.on('send_message')
def handle_send_message(data):
    mittente_id = session.get('utente_id')

    try:
        destinatario_id = int(data.get('destinatario_id'))
    except (TypeError, ValueError):
        emit('error', {'message': 'destinatario_id non valido'})
        return

    testo = data.get('testo', '').strip()

    if not mittente_id or not destinatario_id or not testo:
        emit('error', {'message': 'Dati mancanti o sessione non valida'})
        return

    conn = None
    c = None

    try:
        conn = get_db_connection()
        c = get_cursor(conn)

        # 🔒 Verifica foto profilo
        c.execute(sql("SELECT foto_profilo FROM utenti WHERE id = ?"), (mittente_id,))
        row = c.fetchone()

        if not row or not row["foto_profilo"]:
            emit("error", {
                "message": "Per inviare messaggi devi prima caricare una foto profilo."
            })
            return

        # 🔵 Salvataggio messaggio
        msg_id = chat_invia(mittente_id, destinatario_id, testo)

        # 🔹 Aggiorna visibilità
        conn.execute(sql(
            "UPDATE utenti SET visibile_in_chat = 1 WHERE id = ?"
        ), (mittente_id,))
        conn.commit()

    finally:
        try:
            if c:
                c.close()
        except:
            pass

        if conn:
            try:
                conn.close()
            except:
                pass

    # 🔵 Costruzione oggetto messaggio
    messaggio = {
        'id': msg_id,
        'mittente_id': mittente_id,
        'destinatario_id': destinatario_id,
        'testo': testo,
        'created_at': datetime.now(ZoneInfo("Europe/Rome")).isoformat(),
        'consegnato': True,
        'letto': False
    }

    # 🔵 Invio realtime
    emit('new_message', messaggio, room=f"user_{mittente_id}")
    emit('new_message', messaggio, room=f"user_{destinatario_id}")

    socketio.emit("message_delivered", {
        "id": msg_id,
        "mittente_id": mittente_id,
        "destinatario_id": destinatario_id
    }, room=f"user_{mittente_id}")

    socketio.emit('update_unread_count', {'for_user': mittente_id}, room=f"user_{mittente_id}")
    socketio.emit('update_unread_count', {'for_user': destinatario_id}, room=f"user_{destinatario_id}")

    socketio.emit('chat_threads_update', {'from': mittente_id}, room=f"user_{mittente_id}")
    socketio.emit('chat_threads_update', {'from': mittente_id}, room=f"user_{destinatario_id}")

@socketio.on('chat_aperta')
def handle_chat_aperta(data):
    """Registra quale chat è attualmente aperta da ciascun utente."""
    user_id = session.get('utente_id')
    other_id = data.get('other_id')
    if not user_id or not other_id:
        return
    if 'CHAT_APERTA_UTENTI' not in app.config:
        app.config['CHAT_APERTA_UTENTI'] = {}
    app.config['CHAT_APERTA_UTENTI'][user_id] = int(other_id)

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    user_id = session.get('utente_id')
    other_id = data.get('other_id')
    if not user_id or not other_id:
        return
    try:
        chat_segna_letti(user_id, other_id)

        # 🔥 AGGIORNA LE SPUNTE NELLA CHAT DELL’ALTRO UTENTE
        socketio.emit('messages_read', {'from': user_id}, room=f"user_{other_id}")

        # 🔵 aggiorna contatore per l’utente nella navbar
        socketio.emit('update_unread_count', {'for_user': user_id}, room=f"user_{user_id}")

        # 🔵 aggiorna anche la lista chat
        socketio.emit('chat_threads_update', {'from': other_id}, room=f"user_{user_id}")

        print(f"✅ Messaggi da {other_id} segnati come letti da {user_id}")
    except Exception as e:
        print(f"❌ Errore mark_as_read: {e}")

@socketio.on('chat_chiusa')
def handle_chat_chiusa(data):
    user_id = session.get('utente_id')
    other_id = data.get('other_id')
    if not user_id or not other_id:
        return

    # 🔥 PULIZIA STATO
    if 'CHAT_APERTA_UTENTI' in app.config:
        app.config['CHAT_APERTA_UTENTI'].pop(user_id, None)

    if 'CHAT_ULTIMA_LETTA' not in app.config:
        app.config['CHAT_ULTIMA_LETTA'] = {}
    app.config['CHAT_ULTIMA_LETTA'][user_id] = int(other_id)

    clear_recently_read(user_id)

    # 🔥🔥 AGGIORNA SUBITO LA LISTA CHAT
    socketio.emit('chat_threads_update', {}, room=f"user_{user_id}")

@socketio.on('refresh_threads')
def handle_refresh_threads(data):
    user_id = session.get('utente_id')
    if not user_id:
        return
    socketio.emit("chat_threads_update", {}, room=f"user_{user_id}")

@socketio.on('typing')
def handle_typing(data):
    """
    Gestisce l'indicatore 'sta scrivendo'
    """
    from flask import session

    mittente_id = session.get('utente_id')
    destinatario_id = data.get('to')
    typing = data.get('typing', False)

    if not mittente_id or not destinatario_id:
        return

    # Salva stato (opzionale, ma utile)
    typing_state[(mittente_id, destinatario_id)] = typing

    # Invia SOLO all'altro utente
    socketio.emit(
        'user_typing',
        {
            'from': mittente_id,
            'typing': typing
        },
        room=f"user_{destinatario_id}"
    )


@app.route("/webhook/stripe", methods=["POST"])
def webhook_stripe():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    endpoint_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")

    if not endpoint_secret:
        print("❌ STRIPE_WEBHOOK_SECRET non trovato")
        return "Webhook secret missing", 500

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=endpoint_secret
        )
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    # Gestiamo SOLO il succeeded (gli altri li ignoriamo)
    if event["type"] == "payment_intent.succeeded":
        payment_intent = event["data"]["object"]
        gestisci_pagamento_confermato(payment_intent)

    return "ok", 200

# =====================================================
# 🧹 AUTO CLEANUP VIDEO CALL FANTASMA
# =====================================================

from datetime import datetime, timedelta

def cleanup_video_calls():
    while True:
        conn = None
        try:
            with app.app_context():
                conn = get_db_connection()
                cur = get_cursor(conn)

                # 1️⃣ Trova call zombie
                zombies = cur.execute(sql("""
                    SELECT id, room_name, utente_1, utente_2
                    FROM video_call_log
                    WHERE in_corso = 1
                      AND last_ping IS NOT NULL
                      AND last_ping < CURRENT_TIMESTAMP - INTERVAL '60 seconds'
                """)).fetchall()

                if zombies:
                    # 2️⃣ Chiudi realmente le call
                    cur.execute(sql("""
                        UPDATE video_call_log
                        SET in_corso = 0,
                            ended_at = CURRENT_TIMESTAMP
                        WHERE in_corso = 1
                          AND last_ping IS NOT NULL
                          AND last_ping < CURRENT_TIMESTAMP - INTERVAL '60 seconds'
                    """))

                    conn.commit()

                    # 3️⃣ Notifica agli utenti che non sono più occupati
                    for z in zombies:
                        u1 = z["utente_1"]
                        u2 = z["utente_2"]

                        socketio.emit(
                            "video_busy",
                            {"user_id": u1, "busy": False},
                            room=f"user_{u2}"
                        )
                        socketio.emit(
                            "video_busy",
                            {"user_id": u2, "busy": False},
                            room=f"user_{u1}"
                        )

        except Exception as e:
            print("Errore cleanup video:", e)

        finally:
            # 🔥 QUESTO ERA IL PROBLEMA
            if conn:
                try:
                    conn.close()
                except:
                    pass

        # 🟢 Yield cooperativo per eventlet
        socketio.sleep(30)

# ==========================================================
# 7️⃣ AVVIO SERVER
# ==========================================================
if __name__ == "__main__":
    socketio.run(
        app,
        host="127.0.0.1",
        port=5050,
        debug=True,
        use_reloader=False
    )
