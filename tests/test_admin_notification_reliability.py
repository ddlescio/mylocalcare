import ast
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)


def load_function(name, namespace):
    function = next(
        node for node in APP_TREE.body
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


class FakeCursor:
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.executions = []
        self.close_calls = 0

    def execute(self, query, params=()):
        self.executions.append((query, params))

    def fetchall(self):
        return list(self.rows)

    def close(self):
        self.close_calls += 1


class FakeConnection:
    def __init__(self, cursors):
        self.cursors = list(cursors)
        self.commit_calls = 0
        self.close_calls = 0

    def cursor(self):
        return self.cursors.pop(0)

    def commit(self):
        self.commit_calls += 1

    def close(self):
        self.close_calls += 1


class DeferredThread:
    instances = []

    def __init__(self, *, target, args, daemon):
        self.target = target
        self.args = args
        self.daemon = daemon
        self.started = False
        self.__class__.instances.append(self)

    def start(self):
        self.started = True


class AdminNotificationReliabilityTest(unittest.TestCase):
    def setUp(self):
        DeferredThread.instances = []

    def test_notification_insert_does_not_close_caller_connection(self):
        cursor = FakeCursor()
        connection = FakeConnection([cursor])
        namespace = {
            "get_db_connection": lambda: self.fail(
                "A caller-owned connection must be reused"
            ),
            "get_cursor": lambda conn: conn.cursor(),
            "sql": lambda query: query,
        }
        create_notification = load_function("_crea_notifica", namespace)

        create_notification(
            12,
            "Titolo",
            "Messaggio",
            tipo="admin",
            link="/admin/referenze",
            db_connection=connection,
        )

        self.assertEqual(connection.commit_calls, 1)
        self.assertEqual(connection.close_calls, 0)
        self.assertEqual(cursor.close_calls, 1)
        self.assertEqual(len(cursor.executions), 1)

    def test_deferred_admin_push_keeps_http_path_non_blocking(self):
        list_cursor = FakeCursor(rows=[{"id": 3}, {"id": 9}])
        connection = FakeConnection([list_cursor])
        created = []
        realtime = []
        synchronous_pushes = []
        logs = []
        namespace = {
            "get_db_connection": lambda: self.fail(
                "A caller-owned connection must be reused"
            ),
            "get_cursor": lambda conn: conn.cursor(),
            "sql": lambda query: query,
            "_crea_notifica": (
                lambda *args, **kwargs: created.append((args, kwargs))
            ),
            "emit_update_notifications": realtime.append,
            "invia_push": (
                lambda *args, **kwargs: synchronous_pushes.append(
                    (args, kwargs)
                )
            ),
            "url_for": lambda endpoint: f"/{endpoint}",
            "threading": SimpleNamespace(Thread=DeferredThread),
            "_invia_push_admin_evento_differita": object(),
            "log_exception_safe": (
                lambda *args, **kwargs: logs.append((args, kwargs))
            ),
        }
        notify_admins = load_function("notifica_admin_evento", namespace)

        notify_admins(
            "Nuova referenza",
            "Una referenza attende il controllo.",
            link="/admin/referenze?stato=da_gestire",
            push=True,
            defer_push=True,
            db_connection=connection,
        )

        self.assertEqual([item[0][0] for item in created], [3, 9])
        self.assertTrue(all(
            item[1]["db_connection"] is connection for item in created
        ))
        self.assertEqual(realtime, [3, 9])
        self.assertEqual(synchronous_pushes, [])
        self.assertEqual(connection.close_calls, 0)
        self.assertEqual(list_cursor.close_calls, 1)
        self.assertEqual(logs, [])
        self.assertEqual(len(DeferredThread.instances), 1)
        thread = DeferredThread.instances[0]
        self.assertTrue(thread.started)
        self.assertTrue(thread.daemon)
        self.assertEqual(thread.args[0], (3, 9))
        self.assertEqual(
            thread.args[3],
            "/admin/referenze?stato=da_gestire",
        )


if __name__ == "__main__":
    unittest.main()
