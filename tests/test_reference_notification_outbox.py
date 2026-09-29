import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace

from flask import Flask, g, has_request_context

from reference_notification_outbox import (
    enqueue_reference_response_notifications,
    process_reference_notification_outbox_once,
)
from tests.test_referenze_schema import load_reference_bootstrap


ROOT = Path(__file__).resolve().parents[1]


def load_app_function(name, namespace):
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    exec(
        compile(
            ast.Module(body=[function], type_ignores=[]),
            "app.py",
            "exec",
        ),
        namespace,
    )
    return namespace[name]


class ReferenceNotificationOutboxTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        self.database_path = Path(temporary.name)

        connection = self.connect()
        connection.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                username TEXT,
                ruolo TEXT DEFAULT 'user',
                attivo INTEGER DEFAULT 1,
                sospeso INTEGER DEFAULT 0,
                disattivato_admin INTEGER DEFAULT 0
            );
            INSERT INTO utenti (id, username) VALUES (1, 'owner');
            INSERT INTO utenti (id, username, ruolo)
            VALUES (2, 'admin', 'admin');
        """)
        connection.commit()
        connection.close()

        load_reference_bootstrap(self.connect)()
        connection = self.connect()
        connection.executescript("""
            CREATE TABLE notifiche (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                id_utente INTEGER NOT NULL,
                titolo TEXT,
                messaggio TEXT NOT NULL,
                link TEXT,
                tipo TEXT DEFAULT 'generica',
                letta INTEGER DEFAULT 0,
                data TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (id_utente) REFERENCES utenti(id)
            );
        """)
        self.reference_id = connection.execute("""
            INSERT INTO referenze (
                utente_id, categoria_slug, tipo_rapporto,
                stato_risposta, stato_verifica, risposta_at,
                created_at, updated_at
            ) VALUES (
                1, 'babysitter', 'famiglia',
                'risposta_ricevuta', 'in_coda',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """).lastrowid
        connection.commit()
        connection.close()

    def tearDown(self):
        self.database_path.unlink(missing_ok=True)

    def connect(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def cursor_factory(connection):
        return connection.cursor()

    def enqueue(self, connection):
        return enqueue_reference_response_notifications(
            connection.cursor(),
            lambda query: query,
            reference_id=self.reference_id,
            reference_version=2,
            owner_id=1,
            owner_title="Aggiornamento referenza",
            owner_message="Hai ricevuto una nuova referenza.",
            owner_link="/utente/dashboard#referenze",
            direct=True,
            admin_title="Nuova referenza da controllare",
            admin_message="@owner ha ricevuto una referenza.",
            admin_link="/admin/referenze?stato=da_gestire",
        )

    def test_enqueue_e_atomico_e_idempotente(self):
        connection = self.connect()
        connection.execute("BEGIN IMMEDIATE")
        self.assertEqual(self.enqueue(connection), 2)
        self.assertEqual(self.enqueue(connection), 0)
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM referenze_notifiche_outbox"
            ).fetchone()[0],
            2,
        )
        connection.rollback()
        connection.close()

        check = self.connect()
        self.assertEqual(
            check.execute(
                "SELECT COUNT(*) FROM referenze_notifiche_outbox"
            ).fetchone()[0],
            0,
        )
        check.execute("BEGIN IMMEDIATE")
        self.assertEqual(self.enqueue(check), 2)
        self.assertEqual(self.enqueue(check), 0)
        check.commit()
        self.assertEqual(
            check.execute(
                "SELECT COUNT(*) FROM referenze_notifiche_outbox"
            ).fetchone()[0],
            2,
        )
        check.close()

    def test_worker_committa_notifica_ritenta_push_e_non_duplica(self):
        connection = self.connect()
        connection.execute("BEGIN IMMEDIATE")
        self.enqueue(connection)
        start = datetime(2026, 9, 29, 18, 0, tzinfo=timezone.utc)
        connection.execute(
            "UPDATE referenze_notifiche_outbox SET disponibile_at = ?",
            ((start - timedelta(seconds=1)).isoformat(),),
        )
        connection.commit()
        connection.close()

        order = []
        realtime = []

        def failed_push(user_id, title, body, link):
            visible = self.connect()
            count = visible.execute(
                "SELECT COUNT(*) FROM notifiche WHERE id_utente = ?",
                (user_id,),
            ).fetchone()[0]
            visible.close()
            self.assertEqual(count, 1, "la notifica deve precedere la push")
            order.append("push-failed")
            return False

        def emit(user_id, recipient_kind):
            realtime.append((user_id, recipient_kind))
            order.append(f"realtime-{recipient_kind}")

        first = process_reference_notification_outbox_once(
            connect=self.connect,
            cursor_factory=self.cursor_factory,
            sql=lambda query: query,
            is_postgres=False,
            send_push=failed_push,
            emit_realtime=emit,
            now=start,
            retry_base_seconds=5,
            retry_max_seconds=60,
        )
        self.assertEqual(first, {"claimed": 2, "processed": 1, "retried": 1})
        self.assertEqual(realtime, [(1, "owner")])

        check = self.connect()
        self.assertEqual(
            check.execute("SELECT COUNT(*) FROM notifiche").fetchone()[0],
            2,
        )
        admin_outbox = check.execute("""
            SELECT * FROM referenze_notifiche_outbox
            WHERE destinatario_tipo = 'admin'
        """).fetchone()
        self.assertIsNone(admin_outbox["elaborata_at"])
        self.assertIsNotNone(admin_outbox["notifica_creata_at"])
        self.assertEqual(admin_outbox["tentativi"], 1)
        self.assertIn("push delivery failed", admin_outbox["ultimo_errore"])
        check.close()

        def successful_push(user_id, title, body, link):
            order.append("push-success")
            return True

        second = process_reference_notification_outbox_once(
            connect=self.connect,
            cursor_factory=self.cursor_factory,
            sql=lambda query: query,
            is_postgres=False,
            send_push=successful_push,
            emit_realtime=emit,
            now=start + timedelta(seconds=6),
            retry_base_seconds=5,
            retry_max_seconds=60,
        )
        self.assertEqual(second, {"claimed": 1, "processed": 1, "retried": 0})
        self.assertLess(
            order.index("push-success"),
            order.index("realtime-admin"),
        )

        third = process_reference_notification_outbox_once(
            connect=self.connect,
            cursor_factory=self.cursor_factory,
            sql=lambda query: query,
            is_postgres=False,
            send_push=lambda *args: self.fail("push duplicata"),
            emit_realtime=lambda *args: self.fail("realtime duplicato"),
            now=start + timedelta(seconds=7),
        )
        self.assertEqual(third, {"claimed": 0, "processed": 0, "retried": 0})
        final = self.connect()
        self.assertEqual(
            final.execute("SELECT COUNT(*) FROM notifiche").fetchone()[0],
            2,
        )
        self.assertEqual(
            final.execute("""
                SELECT COUNT(*) FROM referenze_notifiche_outbox
                WHERE elaborata_at IS NOT NULL
            """).fetchone()[0],
            2,
        )
        final.close()

    def test_worker_recupera_un_lease_scaduto(self):
        connection = self.connect()
        connection.execute("BEGIN IMMEDIATE")
        self.enqueue(connection)
        now = datetime(2026, 9, 29, 19, 0, tzinfo=timezone.utc)
        connection.execute("""
            UPDATE referenze_notifiche_outbox
            SET disponibile_at = ?, bloccata_at = ?, blocco_token = 'worker-morto'
        """, (
            (now - timedelta(minutes=10)).isoformat(),
            (now - timedelta(minutes=10)).isoformat(),
        ))
        connection.commit()
        connection.close()

        result = process_reference_notification_outbox_once(
            connect=self.connect,
            cursor_factory=self.cursor_factory,
            sql=lambda query: query,
            is_postgres=False,
            send_push=lambda *args: True,
            emit_realtime=lambda *args: None,
            now=now,
            lease_seconds=300,
        )
        self.assertEqual(result["processed"], 2)


class ReferenceSessionOptOutTest(unittest.TestCase):
    def test_opt_out_non_tocca_backend_sessione_dopo_commit(self):
        app = Flask(__name__)
        app.secret_key = "test"
        backend_calls = []
        namespace = {
            "has_request_context": has_request_context,
            "g": g,
            "_default_save_server_session": (
                lambda *args: backend_calls.append(args)
            ),
        }
        save_session = load_app_function(
            "_save_server_session_with_reference_opt_out",
            namespace,
        )

        with app.test_request_context("/referenze/rispondi", method="POST"):
            g.skip_server_session_save = True
            response = app.make_response("ok")
            save_session(
                app,
                SimpleNamespace(accessed=True),
                response,
            )

        self.assertEqual(backend_calls, [])
        self.assertIn("Cookie", response.headers.get("Vary", ""))


if __name__ == "__main__":
    unittest.main()
