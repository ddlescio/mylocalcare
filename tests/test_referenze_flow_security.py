import ast
import copy
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask, flash, redirect, request, session

from referenze import (
    REFERENCE_CONSENT_VERSION,
    REFERENCE_KEY_ID,
    decrypt_reference_phone,
    encrypt_reference_phone,
    normalize_reference_payload,
)


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "app.py"
APP_SOURCE = APP_PATH.read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)


def function_source(name):
    node = next(
        item
        for item in APP_TREE.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return ast.get_source_segment(APP_SOURCE, node)


def load_function(name, namespace):
    node = next(
        copy.deepcopy(item)
        for item in APP_TREE.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    node.decorator_list = []
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(APP_PATH), "exec"),
        namespace,
    )
    return namespace[name]


def load_reference_bootstrap(connect):
    source = (ROOT / "init_db.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "crea_tabelle_referenze"
    )
    namespace = {
        "IS_POSTGRES": False,
        "get_conn": connect,
        "sql": lambda query: query,
        "dt_col": lambda default=False: (
            "TEXT DEFAULT CURRENT_TIMESTAMP" if default else "TEXT"
        ),
    }
    exec(
        compile(
            ast.Module(body=[function], type_ignores=[]),
            "init_db.py",
            "exec",
        ),
        namespace,
    )
    return namespace["crea_tabelle_referenze"]


class ReferenceFlowSecuritySourceTest(unittest.TestCase):
    def test_reference_email_recipient_is_redacted_from_application_logs(self):
        email_source = function_source("_invia_email")
        invite_source = function_source("_invia_invito_referenza")
        self.assertIn("redact_recipient=False", email_source)
        self.assertIn('destinazione_log = "[recapito-riservato]"', email_source)
        self.assertIn("redact_recipient=True", invite_source)
        self.assertIn('"Message": "[REDACTED]"', email_source)
        self.assertIn('"result": result_log', email_source)
        self.assertIn("build_external_url(", invite_source)
        self.assertIn('"referenza_accesso"', invite_source)
        self.assertIn("token=raw_token", invite_source)
        self.assertNotIn("_external=True", invite_source)

    def test_token_redirect_never_leaks_or_caches_raw_link(self):
        source = function_source("referenza_accesso")
        self.assertIn('response.headers["Referrer-Policy"] = "no-referrer"', source)
        self.assertIn('response.headers["Cache-Control"] = "no-store"', source)
        self.assertIn('response = redirect(url_for("referenza_rispondi"))', source)

    def test_response_write_rechecks_token_and_expiry_atomically(self):
        source = function_source("referenza_rispondi")
        self.assertIn("c.token_hash = ?", source)
        self.assertIn("c.token_consumed_at IS NULL", source)
        self.assertIn("token_not_expired", source)
        self.assertIn('row["token_hash"]', source)
        self.assertIn('direct_answer not in {"0", "1"}', source)

    def test_creation_and_resend_serialize_limits_for_same_user(self):
        creation = function_source("api_referenze_crea")
        resend = function_source("api_referenza_reinvia")
        for source in (creation, resend):
            self.assertIn("_schede_profilo_begin(cur)", source)
            self.assertIn("_schede_profilo_lock_user(cur, user_id)", source)
        self.assertLess(
            creation.index("_schede_profilo_lock_user(cur, user_id)"),
            creation.index("SELECT COUNT(*) AS valore"),
        )
        self.assertIn("c.contatto_purged_at", resend)
        self.assertIn("_registra_fallimento_email_referenza", resend)
        self.assertIn("FOR UPDATE OF r, c", resend)

    def test_sqlite_daily_limit_uses_normalized_datetime_comparison(self):
        creation = function_source("api_referenze_crea")
        self.assertIn(
            'invite_window_clause = "datetime(created_at) >= datetime(?)"',
            creation,
        )
        self.assertIn(
            'cutoff.strftime("%Y-%m-%d %H:%M:%S")',
            creation,
        )

    def test_refusal_or_revocation_cannot_be_used_to_spam_a_new_invite(self):
        creation = function_source("api_referenze_crea")
        duplicate_query = creation.split(
            "SELECT r.id", 1
        )[1].split("LIMIT 1", 1)[0]
        self.assertIn("c.email_hash = ?", duplicate_query)
        self.assertNotIn("r.stato_risposta IN", duplicate_query)
        self.assertNotIn("r.stato_verifica <>", duplicate_query)

    def test_external_reply_category_is_limited_to_owner_services(self):
        response = function_source("referenza_rispondi")
        self.assertIn(
            '_referenze_categorie(cur, int(row["utente_id"]))',
            response,
        )
        self.assertIn(
            'structured["categoria_slug"] not in category_slugs',
            response,
        )

    def test_revocation_removes_contact_authorisation(self):
        revoke = function_source("api_referenza_revoca")
        self.assertIn("autorizza_contatto_verifica = FALSE", revoke)
        self.assertIn("autorizzazione_contatto_at = NULL", revoke)

    def test_reference_notifications_open_reviews_reference_section(self):
        for name in ("admin_referenza_verifica", "referenza_rispondi"):
            self.assertIn(
                'url_for("dashboard") + "#referenze"',
                function_source(name),
            )


class ReferenceEmailFailurePersistenceTest(unittest.TestCase):
    def test_email_failure_is_committed_and_audited(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        database_path = Path(temporary.name)
        connection = sqlite3.connect(database_path)
        connection.executescript("""
            CREATE TABLE referenze_contatti (
                referenza_id INTEGER PRIMARY KEY,
                ultimo_errore_invio TEXT,
                updated_at TEXT
            );
            CREATE TABLE referenze_eventi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referenza_id INTEGER NOT NULL,
                tipo_evento TEXT NOT NULL,
                attore_tipo TEXT NOT NULL
            );
            INSERT INTO referenze_contatti (referenza_id) VALUES (7);
        """)
        connection.commit()

        def event(cursor, reference_id, event_type, actor_type, **_kwargs):
            cursor.execute(
                "INSERT INTO referenze_eventi "
                "(referenza_id, tipo_evento, attore_tipo) VALUES (?, ?, ?)",
                (reference_id, event_type, actor_type),
            )

        namespace = {
            "_schede_profilo_begin": lambda cursor: cursor.execute(
                "BEGIN IMMEDIATE"
            ),
            "_schede_profilo_commit": lambda cursor: cursor.execute("COMMIT"),
            "_schede_profilo_rollback": lambda cursor: cursor.execute(
                "ROLLBACK"
            ),
            "_referenza_evento": event,
            "sql": lambda query: query,
            "log_exception_safe": lambda *args, **kwargs: None,
        }
        persist_failure = load_function(
            "_registra_fallimento_email_referenza", namespace
        )
        cursor = connection.cursor()
        persist_failure(cursor, 7)
        cursor.close()
        connection.close()

        check = sqlite3.connect(database_path)
        error = check.execute(
            "SELECT ultimo_errore_invio FROM referenze_contatti "
            "WHERE referenza_id = 7"
        ).fetchone()[0]
        event_type = check.execute(
            "SELECT tipo_evento FROM referenze_eventi WHERE referenza_id = 7"
        ).fetchone()[0]
        check.close()
        database_path.unlink(missing_ok=True)

        self.assertEqual(error, "Invio email non riuscito")
        self.assertEqual(event_type, "invio_email_fallito")


class ReferenceReplyPersistenceTest(unittest.TestCase):
    MASTER_SECRET = bytes(range(32))

    def setUp(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        self.database_path = Path(temporary.name)

        def connect():
            connection = sqlite3.connect(self.database_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            return connection

        setup_connection = connect()
        setup_connection.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                username TEXT,
                lingua_interfaccia TEXT
            );
            INSERT INTO utenti (id, username, lingua_interfaccia)
            VALUES (1, 'owner', 'it');
        """)
        setup_connection.commit()
        setup_connection.close()
        load_reference_bootstrap(connect)()

        self.connection = connect()
        self.reference_id = self.connection.execute("""
            INSERT INTO referenze (
                utente_id, categoria_slug, tipo_rapporto,
                stato_risposta, stato_verifica, created_at, updated_at
            ) VALUES (
                1, 'babysitter', 'famiglia',
                'in_attesa', 'non_esaminata',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """).lastrowid
        self.connection.execute("""
            INSERT INTO referenze_contatti (
                referenza_id, token_hash, token_expires_at,
                email_cifrata, email_nonce, email_tag,
                email_key_id, email_hash,
                created_at, updated_at
            ) VALUES (
                ?, 'reply-token-hash', '2099-01-01T00:00:00+00:00',
                'fixture-cipher', 'fixture-nonce', 'fixture-tag',
                'references-pii-legacy-test', 'fixture-hash',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """, (self.reference_id,))
        self.connection.commit()

        app = Flask(__name__)
        app.secret_key = "reference-reply-test-secret"
        app.config["IS_POSTGRES"] = False
        self.app = app

        def session_row(cursor):
            cursor.execute("""
                SELECT r.*, c.token_hash, c.token_expires_at,
                       c.token_consumed_at, c.email_key_id,
                       u.username AS utente_username,
                       COALESCE(u.lingua_interfaccia, 'it')
                           AS utente_lingua_interfaccia
                FROM referenze r
                JOIN referenze_contatti c ON c.referenza_id = r.id
                JOIN utenti u ON u.id = r.utente_id
                WHERE r.id = ?
            """, (self.reference_id,))
            return cursor.fetchone()

        def rollback(cursor):
            try:
                cursor.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass

        namespace = {
            "app": app,
            "request": request,
            "session": session,
            "flash": flash,
            "redirect": redirect,
            "render_template": (
                lambda template, **kwargs: f"rendered:{template}"
            ),
            "url_for": lambda endpoint, **kwargs: f"/{endpoint}",
            "get_db_connection": lambda: self.connection,
            "get_cursor": lambda connection: connection.cursor(),
            "_referenza_session_row": session_row,
            "_referenza_presenta_privata": lambda row: dict(row),
            "_referenze_categorie": lambda cursor, user_id: [{
                "slug": "babysitter",
                "label": "Babysitter",
            }],
            "_referenze_categoria_label": lambda slug: slug.title(),
            "verify_csrf": lambda: None,
            "_referenza_bool": lambda value: str(value).casefold() in {
                "1", "true", "on",
            },
            "normalize_reference_payload": normalize_reference_payload,
            "encrypt_reference_phone": encrypt_reference_phone,
            "MASTER_SECRET": self.MASTER_SECRET,
            "REFERENCE_CONSENT_VERSION": REFERENCE_CONSENT_VERSION,
            "REFERENCE_KEY_ID": REFERENCE_KEY_ID,
            "datetime": datetime,
            "timezone": timezone,
            "timedelta": timedelta,
            "_schede_profilo_begin": (
                lambda cursor: cursor.execute("BEGIN IMMEDIATE")
            ),
            "_schede_profilo_commit": lambda cursor: cursor.execute("COMMIT"),
            "_schede_profilo_rollback": rollback,
            "sql": lambda query: query,
            "json": json,
            "invalidate_admin_counters": lambda: None,
            "normalize_language": lambda value: value or "it",
            "translate": lambda key, language: key,
            "_crea_notifica": lambda *args, **kwargs: None,
            "emit_update_notifications": lambda user_id: None,
            "log_exception_safe": lambda *args, **kwargs: None,
            "_referenza_ui_message": lambda message, language=None: message,
        }
        load_function("_referenza_evento", namespace)
        self.route = load_function("referenza_rispondi", namespace)

    def tearDown(self):
        self.connection.close()
        self.database_path.unlink(missing_ok=True)

    def submit(self, *, direct="1", consent="on", phone="+39 333 123 4567"):
        data = {
            "consenso_trattamento": "on",
            "categoria_slug": "babysitter",
            "tipo_rapporto": "famiglia",
            "durata_fascia": "6_12_mesi",
            "esperienza_diretta": direct,
            "testo_referente": "Collaborazione confermata.",
        }
        if phone is not None:
            data["referente_telefono"] = phone
        if consent is not None:
            data["autorizza_contatto_verifica"] = consent
        with self.app.test_request_context(
            "/referenze/rispondi",
            method="POST",
            data=data,
        ):
            session["referenza_access"] = {
                "id": self.reference_id,
                "token_hash": "reply-token-hash",
            }
            return self.route()

    def test_post_salva_telefono_solo_cifrato_e_consuma_token(self):
        response = self.submit()
        self.assertEqual(response.status_code, 200)
        reference = self.connection.execute(
            "SELECT * FROM referenze WHERE id = ?", (self.reference_id,)
        ).fetchone()
        contact = self.connection.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = ?",
            (self.reference_id,),
        ).fetchone()
        event = self.connection.execute(
            "SELECT * FROM referenze_eventi WHERE referenza_id = ?",
            (self.reference_id,),
        ).fetchone()

        self.assertEqual(reference["stato_risposta"], "risposta_ricevuta")
        self.assertEqual(reference["stato_verifica"], "in_coda")
        self.assertEqual(reference["consenso_versione"], "references_2026_v2")
        self.assertNotIn("333", contact["telefono_cifrato"])
        self.assertEqual(
            decrypt_reference_phone(
                contact["telefono_cifrato"],
                contact["telefono_nonce"],
                contact["telefono_tag"],
                self.MASTER_SECRET,
                key_id="references-pii-legacy-test",
            ),
            "+39 333 123 4567",
        )
        self.assertIsNotNone(contact["token_consumed_at"])
        self.assertEqual(event["attore_tipo"], "referente")
        self.assertIsNotNone(event["created_at"])

    def test_rifiuto_azzera_consenso_e_non_salva_telefono(self):
        response = self.submit(direct="0", consent="on")
        self.assertEqual(response.status_code, 200)
        reference = self.connection.execute(
            "SELECT * FROM referenze WHERE id = ?", (self.reference_id,)
        ).fetchone()
        contact = self.connection.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = ?",
            (self.reference_id,),
        ).fetchone()
        self.assertEqual(reference["stato_risposta"], "rifiutata")
        self.assertEqual(reference["autorizza_contatto_verifica"], 0)
        self.assertIsNone(reference["autorizzazione_contatto_at"])
        self.assertIsNone(contact["telefono_cifrato"])

    def test_senza_consenso_e_senza_telefono_invia_la_risposta(self):
        response = self.submit(consent=None, phone=None)
        self.assertEqual(response.status_code, 200)
        reference = self.connection.execute(
            "SELECT * FROM referenze WHERE id = ?", (self.reference_id,)
        ).fetchone()
        contact = self.connection.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = ?",
            (self.reference_id,),
        ).fetchone()
        self.assertEqual(reference["stato_risposta"], "risposta_ricevuta")
        self.assertEqual(reference["autorizza_contatto_verifica"], 0)
        self.assertIsNone(contact["telefono_cifrato"])

    def test_telefono_senza_consenso_non_viene_salvato(self):
        response = self.submit(consent=None, phone="+39 333 123 4567")
        self.assertEqual(response.status_code, 302)
        reference = self.connection.execute(
            "SELECT * FROM referenze WHERE id = ?", (self.reference_id,)
        ).fetchone()
        contact = self.connection.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = ?",
            (self.reference_id,),
        ).fetchone()
        self.assertEqual(reference["stato_risposta"], "in_attesa")
        self.assertIsNone(contact["telefono_cifrato"])
        self.assertIsNone(contact["token_consumed_at"])

    def test_consenso_senza_telefono_non_viene_salvato(self):
        response = self.submit(consent="on", phone=None)
        self.assertEqual(response.status_code, 302)
        reference = self.connection.execute(
            "SELECT stato_risposta FROM referenze WHERE id = ?",
            (self.reference_id,),
        ).fetchone()
        self.assertEqual(reference["stato_risposta"], "in_attesa")


if __name__ == "__main__":
    unittest.main()
