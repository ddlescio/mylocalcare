import ast
import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
