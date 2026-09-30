import ast
import sqlite3
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
APP_TREE = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))


def load_functions(names, namespace):
    functions = [
        node for node in APP_TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in names
    ]
    exec(
        compile(
            ast.Module(body=functions, type_ignores=[]),
            "app.py",
            "exec",
        ),
        namespace,
    )
    return namespace


class SimulatedProcessCrash(BaseException):
    pass


class ReminderStore:
    def __init__(self):
        self.committed = set()


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.fetchone_value = None
        self.executions = []

    def execute(self, query, params=()):
        normalized = " ".join(str(query).split())
        self.executions.append((normalized, params))

        if "SELECT id FROM notifiche" in normalized:
            user_id = int(params[0])
            self.fetchone_value = (
                {"id": user_id}
                if user_id in self.connection.store.committed
                else None
            )
        elif "INSERT INTO notifiche" in normalized:
            self.connection.pending.add(int(params[0]))
        elif normalized == "COMMIT":
            self.connection.commit()
        elif normalized == "ROLLBACK":
            self.connection.rollback()

        return self

    def fetchone(self):
        return self.fetchone_value

    def close(self):
        return None


class FakeConnection:
    def __init__(self, store):
        self.store = store
        self.pending = set()
        self.cursor_instance = FakeCursor(self)
        self.commit_calls = 0
        self.rollback_calls = 0

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.store.committed.update(self.pending)
        self.pending.clear()
        self.commit_calls += 1

    def rollback(self):
        self.pending.clear()
        self.rollback_calls += 1

    def close(self):
        return None


def reminder_users():
    return [
        {
            "id": 1,
            "email": "uno@example.test",
            "nome": "Uno",
            "username": "uno",
            "email_notifiche": 0,
        },
        {
            "id": 2,
            "email": "due@example.test",
            "nome": "Due",
            "username": "due",
            "email_notifiche": 0,
        },
    ]


class ProfileReminderReliabilityTests(unittest.TestCase):
    def build_backend(self, store, emit):
        connections = []

        def connection_factory():
            connection = FakeConnection(store)
            connections.append(connection)
            return connection

        namespace = {
            "app": SimpleNamespace(config={"IS_POSTGRES": False}),
            "get_db_connection": connection_factory,
            "get_cursor": lambda connection: connection.cursor(),
            "get_utenti_profilo_incompleto": (
                lambda db_connection=None: reminder_users()
            ),
            "sql": lambda query: query,
            "emit_update_notifications": emit,
            "invia_push": lambda *args, **kwargs: True,
            "_invia_email": lambda **kwargs: True,
            "log_exception_safe": lambda *args, **kwargs: None,
        }
        load_functions(
            {
                "_reminder_profilo_incompleto_recente",
                "_crea_reminder_profilo_incompleto_se_assente",
                "invia_reminder_profili_incompleti",
            },
            namespace,
        )
        return namespace, connections

    def test_crash_mid_batch_does_not_resend_already_committed_user(self):
        store = ReminderStore()
        emitted = []
        first_attempt = True

        def emit(user_id):
            nonlocal first_attempt
            # Il checkpoint deve essere gia durevole quando iniziano gli
            # effetti esterni (realtime, push ed email).
            self.assertIn(user_id, store.committed)
            emitted.append(user_id)
            if first_attempt:
                first_attempt = False
                raise SimulatedProcessCrash()

        backend, _ = self.build_backend(store, emit)
        send = backend["invia_reminder_profili_incompleti"]

        with self.assertRaises(SimulatedProcessCrash):
            send(dry_run=False)

        self.assertEqual(store.committed, {1})

        result = send(dry_run=False)

        self.assertTrue(result["ok"])
        self.assertEqual(result["saltati_per_recenti"], 1)
        self.assertEqual(result["notifiche_create"], 1)
        self.assertEqual(emitted, [1, 2])
        self.assertEqual(store.committed, {1, 2})

    def test_postgres_claim_uses_transaction_scoped_per_user_lock(self):
        store = ReminderStore()
        namespace, connections = self.build_backend(store, lambda _uid: None)
        namespace["app"].config["IS_POSTGRES"] = True
        claim = namespace["_crea_reminder_profilo_incompleto_se_assente"]
        connection = connections[0] if connections else FakeConnection(store)
        cursor = connection.cursor()

        created = claim(
            connection,
            cursor,
            user_id=7,
            titolo="Titolo",
            messaggio="Messaggio",
            link="/utente/dashboard",
        )

        self.assertTrue(created)
        statements = [query for query, _params in cursor.executions]
        self.assertEqual(statements[0], "BEGIN")
        self.assertIn("pg_advisory_xact_lock", statements[1])
        self.assertIn("SELECT id FROM notifiche", statements[2])
        self.assertIn("INSERT INTO notifiche", statements[3])
        self.assertEqual(store.committed, {7})

    def test_sqlite_claim_is_committed_and_deduplicated_immediately(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute("""
            CREATE TABLE notifiche (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                id_utente INTEGER NOT NULL,
                titolo TEXT NOT NULL,
                messaggio TEXT NOT NULL,
                link TEXT,
                tipo TEXT NOT NULL,
                letta INTEGER NOT NULL DEFAULT 0,
                data TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        namespace = {
            "app": SimpleNamespace(config={"IS_POSTGRES": False}),
            "sql": lambda query: query,
        }
        load_functions(
            {
                "_reminder_profilo_incompleto_recente",
                "_crea_reminder_profilo_incompleto_se_assente",
            },
            namespace,
        )
        claim = namespace["_crea_reminder_profilo_incompleto_se_assente"]

        first = claim(
            connection,
            connection.cursor(),
            user_id=9,
            titolo="Titolo",
            messaggio="Messaggio",
            link="/utente/dashboard",
        )
        second = claim(
            connection,
            connection.cursor(),
            user_id=9,
            titolo="Titolo",
            messaggio="Messaggio",
            link="/utente/dashboard",
        )

        self.assertTrue(first)
        self.assertFalse(second)
        count = connection.execute(
            "SELECT COUNT(*) FROM notifiche WHERE id_utente = 9"
        ).fetchone()[0]
        self.assertEqual(count, 1)
        connection.close()


if __name__ == "__main__":
    unittest.main()
