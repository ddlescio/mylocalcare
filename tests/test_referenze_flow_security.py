import ast
import copy
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask, flash, g, jsonify, redirect, request, session

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
    def test_completed_reference_moves_out_of_sent_requests(self):
        classify = load_function("_referenza_private_section", {})

        for state in ("verificata", "non_verificabile"):
            with self.subTest(state=state):
                self.assertEqual(
                    classify({
                        "stato_risposta": "risposta_ricevuta",
                        "stato_verifica": state,
                        "pubblicazione_approvata_admin": 0,
                        "visibile_profilo": 0,
                        "revocata_at": None,
                        "cancellata_at": None,
                    }),
                    "ricevuta",
                )
        for state in ("non_esaminata", "in_coda", "non_confermata"):
            with self.subTest(state=state):
                self.assertEqual(
                    classify({
                        "stato_risposta": "risposta_ricevuta",
                        "stato_verifica": state,
                    }),
                    "richiesta",
                )
        self.assertEqual(
            classify({
                "stato_risposta": "risposta_ricevuta",
                "stato_verifica": "verificata",
                "revocata_at": "2026-09-29T10:00:00+00:00",
            }),
            "richiesta",
        )

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

    def test_invite_contact_sharing_consent_is_enforced_server_side(self):
        flask_app = Flask(__name__)
        database_touched = []
        route = load_function("api_referenze_crea", {
            "verify_csrf": lambda: None,
            "_referenza_request_payload": lambda: request.form.to_dict(),
            "_referenza_bool": lambda value: str(value or "").casefold() in {
                "1", "true", "on", "yes", "si", "sì",
            },
            "jsonify": jsonify,
            "_referenza_ui_message": lambda message, language=None: message,
            "get_db_connection": lambda: database_touched.append(True),
        })
        with flask_app.test_request_context(
            "/api/utente/referenze",
            method="POST",
            data={"referente_email": "ref@example.test"},
        ):
            response, status = route()

        self.assertEqual(status, 400)
        self.assertFalse(response.get_json()["ok"])
        self.assertIn("Conferma", response.get_json()["message"])
        self.assertEqual(database_touched, [])
        creation = function_source("api_referenze_crea")
        self.assertIn('payload.get("conferma_condivisione_recapito")', creation)
        self.assertIn('"conferma_condivisione_recapito": True', creation)

    def test_resend_and_restore_require_fresh_contact_confirmation(self):
        flask_app = Flask(__name__)
        for function_name in (
            "api_referenza_reinvia",
            "api_referenza_ripristina",
        ):
            database_touched = []
            route = load_function(function_name, {
                "verify_csrf": lambda: None,
                "_referenza_request_payload": lambda: request.get_json(
                    silent=True
                ) or {},
                "_referenza_bool": lambda value: str(
                    value or ""
                ).casefold() in {"1", "true", "on", "yes", "si", "sì"},
                "jsonify": jsonify,
                "_referenza_ui_message": (
                    lambda message, language=None: message
                ),
                "get_db_connection": lambda: database_touched.append(True),
            })
            with flask_app.test_request_context(
                "/api/utente/referenze/9/action",
                method="POST",
                json={},
            ):
                response, status = route(9)

            self.assertEqual(status, 400, function_name)
            self.assertFalse(response.get_json()["ok"], function_name)
            self.assertEqual(database_touched, [], function_name)

            source = function_source(function_name)
            self.assertIn(
                'payload.get("conferma_condivisione_recapito")',
                source,
            )
            self.assertIn(
                'dettagli={"conferma_condivisione_recapito": True}',
                source,
            )

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

    def test_restore_creates_a_new_one_time_link_and_requires_fresh_consent(self):
        restore = function_source("api_referenza_ripristina")
        self.assertIn("_schede_profilo_lock_user(cur, user_id)", restore)
        self.assertIn('row["stato_risposta"] != "revocata"', restore)
        self.assertIn("raw_token = generate_reference_token()", restore)
        self.assertIn("token_consumed_at = NULL", restore)
        self.assertIn("token_hash = ?", restore)
        self.assertIn("stato_risposta = 'in_attesa'", restore)
        self.assertIn("autorizza_pubblicazione = FALSE", restore)
        self.assertIn("autorizza_contatto_verifica = FALSE", restore)
        self.assertIn("risposta_at = NULL", restore)
        self.assertIn('"invito_ripristinato"', restore)
        self.assertIn("_invia_invito_referenza", restore)

    def test_delete_is_soft_delete_with_immediate_contact_purge(self):
        delete = function_source("api_referenza_elimina")
        self.assertIn('row["stato_risposta"] == "revocata"', delete)
        self.assertIn('row["stato_verifica"] in {', delete)
        self.assertIn('"verificata", "non_verificabile"', delete)
        self.assertIn('expected_version = int(payload.get("versione")', delete)
        self.assertIn("AND versione = ?", delete)
        self.assertIn("stato_risposta = 'cancellata'", delete)
        self.assertIn("email_cifrata = NULL", delete)
        self.assertIn("email_hash = NULL", delete)
        self.assertIn("telefono_cifrato = NULL", delete)
        self.assertIn("token_hash = NULL", delete)
        self.assertIn("contatto_purged_at = CURRENT_TIMESTAMP", delete)
        self.assertIn('"richiesta_cancellata_utente"', delete)
        self.assertIn('"referenza_cancellata_utente"', delete)

    def test_reference_notifications_open_reviews_reference_section(self):
        for name in ("admin_referenza_verifica", "referenza_rispondi"):
            self.assertIn(
                'url_for("dashboard") + "#referenze"',
                function_source(name),
            )


class ReferenceRequestLifecycleTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        self.database_path = Path(temporary.name)
        setup_connection = sqlite3.connect(self.database_path)
        setup_connection.execute("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL
            )
        """)
        setup_connection.commit()
        setup_connection.close()

        load_reference_bootstrap(
            lambda: sqlite3.connect(self.database_path)
        )()
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute(
            "INSERT INTO utenti (id, username) VALUES (?, ?)",
            (7, "utente7"),
        )
        self.connection.execute("""
            INSERT INTO referenze (
                id, utente_id, categoria_slug, tipo_rapporto,
                stato_risposta, stato_verifica, revocata_at
            ) VALUES (?, ?, ?, ?, 'revocata', 'revocata', CURRENT_TIMESTAMP)
        """, (31, 7, "babysitter", "famiglia"))
        self.connection.execute("""
            INSERT INTO referenze_contatti (
                referenza_id, token_hash, token_expires_at,
                numero_invii, ultimo_invio_at
            ) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
        """, (31, "old-hash", "2099-01-01T00:00:00+00:00"))
        self.connection.commit()

        self.app = Flask(__name__)
        self.app.config.update(SECRET_KEY="test", IS_POSTGRES=False)
        self.sent_tokens = []

        def rollback(cursor):
            try:
                cursor.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass

        def event(
            cursor,
            reference_id,
            event_type,
            actor_type,
            *,
            attore_utente_id=None,
            dettagli=None,
        ):
            cursor.execute("""
                INSERT INTO referenze_eventi (
                    referenza_id, tipo_evento, attore_tipo,
                    attore_utente_id, dettagli_snapshot
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                reference_id,
                event_type,
                actor_type,
                attore_utente_id,
                json.dumps(dettagli) if dettagli else None,
            ))

        namespace = {
            "app": self.app,
            "g": g,
            "jsonify": jsonify,
            "verify_csrf": lambda: None,
            "_referenza_request_payload": lambda: request.get_json(
                silent=True
            ) or {},
            "_referenza_bool": lambda value: str(
                value or ""
            ).casefold() in {"1", "true", "on", "yes", "si", "sì"},
            "get_db_connection": lambda: self.connection,
            "get_cursor": lambda connection: connection.cursor(),
            "get_interface_language": lambda: "it",
            "_schede_profilo_begin": (
                lambda cursor: cursor.execute("BEGIN IMMEDIATE")
            ),
            "_schede_profilo_lock_user": lambda cursor, user_id: None,
            "_schede_profilo_commit": lambda cursor: cursor.execute("COMMIT"),
            "_schede_profilo_rollback": rollback,
            "_referenza_decrypt_contact": lambda row: {
                **dict(row),
                "referente_email": "ref@example.test",
                "referente_nome": "Referente",
            },
            "generate_reference_token": lambda: "new-raw-token",
            "hash_reference_token": lambda token: f"hash:{token}",
            "REFERENCE_INVITE_DAYS": 14,
            "REFERENCE_MAX_SENDS": 3,
            "datetime": datetime,
            "timezone": timezone,
            "timedelta": timedelta,
            "sql": lambda query: query,
            "_referenza_evento": event,
            "_referenza_ui_message": lambda message, language=None: message,
            "_invia_invito_referenza": (
                lambda email, name, username, token, language=None: (
                    self.sent_tokens.append(token) or True
                )
            ),
            "_registra_fallimento_email_referenza": lambda *args: None,
            "log_exception_safe": lambda *args, **kwargs: None,
        }
        self.restore = load_function("api_referenza_ripristina", namespace)
        self.delete = load_function("api_referenza_elimina", namespace)

    def tearDown(self):
        self.connection.close()
        self.database_path.unlink(missing_ok=True)

    def call_as_owner(
        self,
        function,
        *,
        reference_id=31,
        contact_confirmation=False,
        version=None,
    ):
        payload = {}
        if contact_confirmation:
            payload["conferma_condivisione_recapito"] = True
        if version is not None:
            payload["versione"] = version
        with self.app.test_request_context("/", method="POST", json=payload):
            g.utente = {"id": 7}
            return function(reference_id)

    def test_restore_replaces_token_and_clears_old_reply_state(self):
        response = self.call_as_owner(
            self.restore,
            contact_confirmation=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        reference = self.connection.execute(
            "SELECT * FROM referenze WHERE id = 31"
        ).fetchone()
        contact = self.connection.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = 31"
        ).fetchone()
        events = self.connection.execute(
            "SELECT tipo_evento FROM referenze_eventi WHERE referenza_id = 31"
        ).fetchall()

        self.assertEqual(reference["stato_risposta"], "in_attesa")
        self.assertEqual(reference["stato_verifica"], "non_esaminata")
        self.assertIsNone(reference["revocata_at"])
        self.assertEqual(contact["token_hash"], "hash:new-raw-token")
        self.assertIsNone(contact["token_consumed_at"])
        self.assertEqual(contact["numero_invii"], 2)
        self.assertEqual(self.sent_tokens, ["new-raw-token"])
        self.assertIn(
            "invito_ripristinato",
            {row["tipo_evento"] for row in events},
        )

    def test_delete_hides_request_and_purges_contact_bundle(self):
        self.connection.execute("""
            UPDATE referenze_contatti
            SET email_cifrata = 'cipher', email_nonce = 'nonce',
                email_tag = 'tag', email_key_id = 'v1',
                email_hash = 'hash', nome_cifrato = 'name',
                nome_nonce = 'nonce', nome_tag = 'tag'
            WHERE referenza_id = 31
        """)
        self.connection.commit()

        version = self.connection.execute(
            "SELECT versione FROM referenze WHERE id = 31"
        ).fetchone()[0]
        response = self.call_as_owner(self.delete, version=version)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        reference = self.connection.execute(
            "SELECT * FROM referenze WHERE id = 31"
        ).fetchone()
        contact = self.connection.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = 31"
        ).fetchone()
        self.assertEqual(reference["stato_risposta"], "cancellata")
        self.assertIsNone(reference["revocata_at"])
        self.assertIsNotNone(reference["cancellata_at"])
        for column in (
            "email_cifrata", "email_hash", "nome_cifrato",
            "telefono_cifrato", "messaggio_invito_cifrato", "token_hash",
        ):
            self.assertIsNone(contact[column])
        self.assertIsNotNone(contact["contatto_purged_at"])

    def test_owner_can_delete_verified_received_reference_directly(self):
        self.connection.execute("""
            INSERT INTO referenze (
                id, utente_id, categoria_slug, tipo_rapporto,
                stato_risposta, stato_verifica, esperienza_diretta,
                visibile_profilo, risposta_at, verificata_at
            ) VALUES (?, ?, ?, ?, 'risposta_ricevuta', 'verificata',
                      1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (32, 7, "caregiver", "famiglia"))
        self.connection.execute("""
            INSERT INTO referenze_contatti (
                referenza_id, email_cifrata, email_nonce, email_tag,
                email_key_id, email_hash, nome_cifrato, nome_nonce, nome_tag,
                token_hash, token_expires_at
            ) VALUES (?, 'cipher', 'nonce', 'tag', 'v1', 'hash',
                      'name', 'nonce', 'tag', 'token',
                      '2099-01-01T00:00:00+00:00')
        """, (32,))
        self.connection.commit()
        version = self.connection.execute(
            "SELECT versione FROM referenze WHERE id = 32"
        ).fetchone()[0]

        response = self.call_as_owner(
            self.delete,
            reference_id=32,
            version=version,
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual(response.get_json()["tipo"], "referenza")
        reference = self.connection.execute(
            "SELECT * FROM referenze WHERE id = 32"
        ).fetchone()
        contact = self.connection.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = 32"
        ).fetchone()
        event = self.connection.execute(
            "SELECT tipo_evento FROM referenze_eventi "
            "WHERE referenza_id = 32 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(reference["stato_risposta"], "cancellata")
        self.assertEqual(reference["stato_verifica"], "revocata")
        self.assertEqual(reference["visibile_profilo"], 0)
        self.assertEqual(reference["pubblicazione_approvata_admin"], 0)
        self.assertIsNotNone(reference["cancellata_at"])
        self.assertIsNone(contact["email_cifrata"])
        self.assertIsNone(contact["token_hash"])
        self.assertIsNotNone(contact["contatto_purged_at"])
        self.assertEqual(event["tipo_evento"], "referenza_cancellata_utente")

    def test_delete_rejects_stale_version_without_changing_reference(self):
        current = self.connection.execute(
            "SELECT versione FROM referenze WHERE id = 31"
        ).fetchone()[0]
        response = self.call_as_owner(self.delete, version=current + 1)

        response_body, status_code = response
        self.assertEqual(status_code, 409)
        self.assertFalse(response_body.get_json()["ok"])
        row = self.connection.execute(
            "SELECT stato_risposta, versione FROM referenze WHERE id = 31"
        ).fetchone()
        self.assertEqual(row["stato_risposta"], "revocata")
        self.assertEqual(row["versione"], current)


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
        self.admin_notifications = []

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
            "notifica_admin_evento": (
                lambda *args, **kwargs: self.admin_notifications.append(
                    {"args": args, "kwargs": kwargs}
                )
            ),
            "log_exception_safe": lambda *args, **kwargs: None,
            "_referenza_ui_message": lambda message, language=None: message,
        }
        load_function("_referenza_evento", namespace)
        self.route = load_function("referenza_rispondi", namespace)

    def tearDown(self):
        self.connection.close()
        self.database_path.unlink(missing_ok=True)

    def submit(
        self,
        *,
        direct="1",
        processing_consent="on",
        consent="on",
        phone="+39 333 123 4567",
        publication=None,
        legacy_text_consent=None,
    ):
        data = {
            "categoria_slug": "babysitter",
            "tipo_rapporto": "famiglia",
            "durata_fascia": "6_12_mesi",
            "esperienza_diretta": direct,
            "testo_referente": "Collaborazione confermata.",
        }
        if processing_consent is not None:
            data["consenso_trattamento"] = processing_consent
        if phone is not None:
            data["referente_telefono"] = phone
        if consent is not None:
            data["autorizza_contatto_verifica"] = consent
        if publication is not None:
            data["autorizza_pubblicazione"] = publication
        if legacy_text_consent is not None:
            data["autorizza_testo_pubblico"] = legacy_text_consent
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

    def test_senza_consenso_privacy_la_risposta_non_viene_salvata(self):
        response = self.submit(processing_consent=None)
        self.assertEqual(response.status_code, 302)
        reference = self.connection.execute(
            "SELECT stato_risposta, consenso_trattamento_at "
            "FROM referenze WHERE id = ?",
            (self.reference_id,),
        ).fetchone()
        contact = self.connection.execute(
            "SELECT token_consumed_at FROM referenze_contatti "
            "WHERE referenza_id = ?",
            (self.reference_id,),
        ).fetchone()

        self.assertEqual(reference["stato_risposta"], "in_attesa")
        self.assertIsNone(reference["consenso_trattamento_at"])
        self.assertIsNone(contact["token_consumed_at"])

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
        self.assertEqual(reference["consenso_versione"], "references_2026_v3")
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
        self.assertEqual(len(self.admin_notifications), 1)
        notification = self.admin_notifications[0]
        self.assertIn("Nuova referenza", notification["args"][0])
        self.assertEqual(
            notification["kwargs"]["link"],
            "/admin_referenze",
        )
        self.assertTrue(notification["kwargs"]["push"])
        self.assertTrue(notification["kwargs"]["defer_push"])
        self.assertIs(
            notification["kwargs"]["db_connection"],
            self.connection,
        )

    def test_unico_consenso_pubblica_scheda_e_testo_compilato(self):
        response = self.submit(publication="on")
        self.assertEqual(response.status_code, 200)
        reference = self.connection.execute(
            "SELECT autorizza_pubblicazione, autorizza_testo_pubblico "
            "FROM referenze WHERE id = ?",
            (self.reference_id,),
        ).fetchone()
        self.assertEqual(reference["autorizza_pubblicazione"], 1)
        self.assertEqual(reference["autorizza_testo_pubblico"], 1)

    def test_client_obsoleto_non_crea_consensi_pubblici_incoerenti(self):
        response = self.submit(legacy_text_consent="on")
        self.assertEqual(response.status_code, 200)
        reference = self.connection.execute(
            "SELECT autorizza_pubblicazione, autorizza_testo_pubblico "
            "FROM referenze WHERE id = ?",
            (self.reference_id,),
        ).fetchone()
        self.assertEqual(reference["autorizza_pubblicazione"], 0)
        self.assertEqual(reference["autorizza_testo_pubblico"], 0)

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
        self.assertEqual(self.admin_notifications, [])

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
