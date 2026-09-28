import ast
import copy
import json
import sqlite3
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)


def _app_function(name):
    for node in APP_TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            selected = copy.deepcopy(node)
            selected.decorator_list = []
            return selected
    raise AssertionError(f"Funzione {name} non trovata")


class ReferenceVisibilityEndpointTest(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript("""
            CREATE TABLE referenze (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                versione INTEGER NOT NULL DEFAULT 1,
                stato_risposta TEXT NOT NULL,
                stato_verifica TEXT NOT NULL,
                autorizza_pubblicazione INTEGER NOT NULL DEFAULT 0,
                pubblicazione_approvata_admin INTEGER NOT NULL DEFAULT 0,
                visibile_profilo INTEGER NOT NULL DEFAULT 1,
                revocata_at TEXT,
                cancellata_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE referenze_eventi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referenza_id INTEGER NOT NULL,
                tipo_evento TEXT NOT NULL,
                attore_tipo TEXT NOT NULL,
                attore_utente_id INTEGER,
                dettagli_snapshot TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO referenze (
                id, utente_id, versione, stato_risposta, stato_verifica,
                autorizza_pubblicazione, pubblicazione_approvata_admin,
                visibile_profilo
            ) VALUES (
                10, 7, 2, 'risposta_ricevuta', 'non_verificabile',
                1, 1, 1
            );
        """)
        self.connection.commit()

        class NonClosingConnection:
            def __init__(self, connection):
                self.connection = connection

            def cursor(self):
                return self.connection.cursor()

            def close(self):
                return None

            def __getattr__(self, name):
                return getattr(self.connection, name)

        self.payload = {"versione": 2, "visibile_profilo": 0}
        request = SimpleNamespace(
            form={},
            get_json=lambda silent=True: dict(self.payload),
        )

        def event(cursor, reference_id, event_type, actor_type, **kwargs):
            cursor.execute("""
                INSERT INTO referenze_eventi (
                    referenza_id, tipo_evento, attore_tipo,
                    attore_utente_id, dettagli_snapshot
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                reference_id,
                event_type,
                actor_type,
                kwargs.get("attore_utente_id"),
                json.dumps(kwargs.get("dettagli") or {}, sort_keys=True),
            ))

        namespace = {
            "request": request,
            "verify_csrf": lambda: None,
            "jsonify": lambda value: value,
            "get_interface_language": lambda: "it",
            "_referenza_ui_message": lambda message, language=None: message,
            "get_db_connection": lambda: NonClosingConnection(self.connection),
            "get_cursor": lambda connection: connection.cursor(),
            "_schede_profilo_begin": (
                lambda cursor: cursor.execute("BEGIN IMMEDIATE")
            ),
            "_schede_profilo_commit": lambda cursor: cursor.execute("COMMIT"),
            "_schede_profilo_rollback": (
                lambda cursor: cursor.execute("ROLLBACK")
            ),
            "_referenza_evento": event,
            "log_exception_safe": lambda *args, **kwargs: None,
            "sql": lambda query: query,
            "app": SimpleNamespace(config={"IS_POSTGRES": False}),
            "g": SimpleNamespace(utente={"id": 7}),
        }
        exec(
            compile(
                ast.Module(
                    body=[_app_function("api_referenza_visibilita")],
                    type_ignores=[],
                ),
                "app.py",
                "exec",
            ),
            namespace,
        )
        self.endpoint = namespace["api_referenza_visibilita"]

    def tearDown(self):
        self.connection.close()

    def test_owner_can_hide_and_action_is_audited(self):
        result = self.endpoint(10)
        row = self.connection.execute(
            "SELECT visibile_profilo, versione FROM referenze WHERE id = 10"
        ).fetchone()
        event = self.connection.execute(
            "SELECT * FROM referenze_eventi WHERE referenza_id = 10"
        ).fetchone()

        self.assertTrue(result["ok"])
        self.assertEqual(tuple(row), (0, 3))
        self.assertEqual(event["tipo_evento"], "visibilita_profilo_aggiornata")
        self.assertEqual(event["attore_utente_id"], 7)

    def test_unapproved_reference_cannot_be_shown(self):
        self.connection.execute("""
            UPDATE referenze
            SET pubblicazione_approvata_admin = 0,
                visibile_profilo = 0
            WHERE id = 10
        """)
        self.connection.commit()
        self.payload["visibile_profilo"] = 1

        result, status = self.endpoint(10)
        self.assertEqual(status, 409)
        self.assertFalse(result["ok"])
        row = self.connection.execute(
            "SELECT visibile_profilo, versione FROM referenze WHERE id = 10"
        ).fetchone()
        self.assertEqual(tuple(row), (0, 2))

    def test_stale_version_is_rejected(self):
        self.payload["versione"] = 1
        result, status = self.endpoint(10)
        self.assertEqual(status, 409)
        self.assertFalse(result["ok"])
        self.assertEqual(
            self.connection.execute(
                "SELECT COUNT(*) FROM referenze_eventi"
            ).fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
