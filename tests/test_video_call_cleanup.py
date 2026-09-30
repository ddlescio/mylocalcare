from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from video_call_cleanup import (
    LEASE_ACQUIRED,
    LEASE_BUSY,
    LEASE_UNAVAILABLE,
    acquire_video_cleanup_lease,
    claim_stale_video_calls,
    process_video_cleanup_once,
    video_cleanup_runtime_enabled,
)


ROOT = Path(__file__).resolve().parents[1]


class FakeRedis:
    def __init__(self, *, acquired=True, broken=False):
        self.acquired = acquired
        self.broken = broken
        self.values = {}

    def set(self, key, value, **kwargs):
        if self.broken:
            raise ConnectionError("redis unavailable")
        if not self.acquired:
            return False
        if kwargs.get("nx") and key in self.values:
            return False
        self.values[key] = value
        return True

    def eval(self, _script, _number_of_keys, key, token):
        if self.values.get(key) != token:
            return 0
        del self.values[key]
        return 1


class VideoCallCleanupTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        self.database_path = Path(temporary.name)

        connection = self.connect()
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("""
            CREATE TABLE video_call_log (
                id INTEGER PRIMARY KEY,
                room_name TEXT NOT NULL,
                utente_1 INTEGER NOT NULL,
                utente_2 INTEGER NOT NULL,
                in_corso INTEGER NOT NULL DEFAULT 1,
                last_ping TEXT,
                ended_at TEXT
            )
        """)
        sqlite_timestamp = "%Y-%m-%d %H:%M:%S"
        stale = (
            datetime.now(timezone.utc) - timedelta(minutes=3)
        ).strftime(sqlite_timestamp)
        fresh = datetime.now(timezone.utc).strftime(sqlite_timestamp)
        connection.executemany("""
            INSERT INTO video_call_log (
                id, room_name, utente_1, utente_2, in_corso, last_ping
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (1, "stale-a", 10, 20, 1, stale),
            (2, "stale-b", 30, 40, 1, stale),
            (3, "fresh", 50, 60, 1, fresh),
            (4, "closed", 70, 80, 0, stale),
        ])
        connection.commit()
        connection.close()

    def tearDown(self):
        self.database_path.unlink(missing_ok=True)

    def connect(self):
        connection = sqlite3.connect(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def cursor_factory(connection):
        return connection.cursor()

    def claim(self, connection):
        return claim_stale_video_calls(
            connection,
            cursor_factory=self.cursor_factory,
            sql_adapter=lambda query: query,
            stale_before_sql="datetime('now', '-60 seconds')",
        )

    def test_runtime_guard_esclude_job_e_cron(self):
        self.assertTrue(video_cleanup_runtime_enabled("web"))
        self.assertTrue(video_cleanup_runtime_enabled("realtime"))
        self.assertFalse(video_cleanup_runtime_enabled("job"))
        self.assertFalse(video_cleanup_runtime_enabled("cron"))
        self.assertFalse(video_cleanup_runtime_enabled(None))

        app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn(
            "if video_cleanup_runtime_enabled(APP_RUNTIME_ROLE):",
            app_source,
        )

    def test_lease_distingue_acquisito_occupato_e_redis_non_disponibile(self):
        status, token = acquire_video_cleanup_lease(
            FakeRedis(acquired=True), token_factory=lambda: "owner"
        )
        self.assertEqual((status, token), (LEASE_ACQUIRED, "owner"))

        status, token = acquire_video_cleanup_lease(FakeRedis(acquired=False))
        self.assertEqual((status, token), (LEASE_BUSY, None))

        status, token = acquire_video_cleanup_lease(FakeRedis(broken=True))
        self.assertEqual((status, token), (LEASE_UNAVAILABLE, None))

    def test_update_returning_restituisce_solo_righe_cambiate(self):
        connection = self.connect()
        first_claim = self.claim(connection)
        second_claim = self.claim(connection)
        connection.close()

        self.assertEqual({row["id"] for row in first_claim}, {1, 2})
        self.assertEqual(second_claim, [])

        check = self.connect()
        active_ids = {
            row[0]
            for row in check.execute(
                "SELECT id FROM video_call_log WHERE in_corso = 1"
            ).fetchall()
        }
        check.close()
        self.assertEqual(active_ids, {3})

    def test_due_processi_concorrenti_non_prendono_la_stessa_riga(self):
        def run_claim():
            connection = self.connect()
            try:
                return [row["id"] for row in self.claim(connection)]
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(executor.map(lambda _index: run_claim(), range(2)))

        claimed_ids = [item for group in claims for item in group]
        self.assertCountEqual(claimed_ids, [1, 2])
        self.assertEqual(len(claimed_ids), len(set(claimed_ids)))

    def test_fallback_senza_redis_notifica_ogni_zombie_una_sola_volta(self):
        emitted = []
        result = process_video_cleanup_once(
            redis_client=FakeRedis(broken=True),
            connection_factory=self.connect,
            cursor_factory=self.cursor_factory,
            sql_adapter=lambda query: query,
            stale_before_sql="datetime('now', '-60 seconds')",
            emit=lambda event, payload, **kwargs: emitted.append(
                (event, payload, kwargs)
            ),
        )
        second_result = process_video_cleanup_once(
            redis_client=FakeRedis(broken=True),
            connection_factory=self.connect,
            cursor_factory=self.cursor_factory,
            sql_adapter=lambda query: query,
            stale_before_sql="datetime('now', '-60 seconds')",
            emit=lambda event, payload, **kwargs: emitted.append(
                (event, payload, kwargs)
            ),
        )

        self.assertEqual(result["lease_status"], LEASE_UNAVAILABLE)
        self.assertEqual(result["claimed_count"], 2)
        self.assertEqual(result["emitted_count"], 2)
        self.assertEqual(second_result["claimed_count"], 0)
        self.assertEqual(len(emitted), 4)
        self.assertCountEqual(
            [item[1]["user_id"] for item in emitted],
            [10, 20, 30, 40],
        )

    def test_lease_riuscito_impedisce_un_secondo_giro_nella_stessa_finestra(self):
        redis = FakeRedis()
        emitted = []

        first = process_video_cleanup_once(
            redis_client=redis,
            connection_factory=self.connect,
            cursor_factory=self.cursor_factory,
            sql_adapter=lambda query: query,
            stale_before_sql="datetime('now', '-60 seconds')",
            emit=lambda event, payload, **kwargs: emitted.append(
                (event, payload, kwargs)
            ),
        )
        second = process_video_cleanup_once(
            redis_client=redis,
            connection_factory=lambda: self.fail(
                "un lease occupato non deve neppure aprire il database"
            ),
            cursor_factory=self.cursor_factory,
            sql_adapter=lambda query: query,
            stale_before_sql="datetime('now', '-60 seconds')",
            emit=lambda *_args, **_kwargs: self.fail(
                "un lease occupato non deve emettere eventi"
            ),
        )

        self.assertEqual(first["lease_status"], LEASE_ACQUIRED)
        self.assertEqual(second["lease_status"], LEASE_BUSY)
        self.assertEqual(first["claimed_count"], 2)
        self.assertEqual(second["claimed_count"], 0)
        self.assertEqual(len(emitted), 4)


if __name__ == "__main__":
    unittest.main()
