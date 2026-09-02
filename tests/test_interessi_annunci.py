import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from interessi_annunci import imposta_interesse_annuncio


SCHEMA_INTERESSI = """
    CREATE TABLE interessi_annunci (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        annuncio_id INTEGER NOT NULL,
        utente_interessato_id INTEGER NOT NULL,
        attivo INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        disattivato_at TEXT,
        ultima_notifica_at TEXT,
        chat_opened_at TEXT,
        UNIQUE (annuncio_id, utente_interessato_id)
    )
"""


class InteressiAnnunciTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(SCHEMA_INTERESSI)

    def tearDown(self):
        self.conn.close()

    def test_attivazione_e_retry_sono_idempotenti(self):
        now = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)

        prima = imposta_interesse_annuncio(
            self.conn, 10, 20, True, now=now
        )
        retry = imposta_interesse_annuncio(
            self.conn, 10, 20, True, now=now + timedelta(seconds=1)
        )

        self.assertTrue(prima["transizione"])
        self.assertTrue(prima["notifica"])
        self.assertFalse(retry["transizione"])
        self.assertFalse(retry["notifica"])
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM interessi_annunci"
            ).fetchone()[0],
            1,
        )

    def test_attivazioni_concorrenti_producono_una_sola_transizione(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "interessi.sqlite3"
            setup_conn = sqlite3.connect(database_path)
            setup_conn.execute(SCHEMA_INTERESSI)
            setup_conn.close()

            barrier = threading.Barrier(2)
            now = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)

            def attiva():
                conn = sqlite3.connect(database_path, timeout=5)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA busy_timeout = 5000")
                barrier.wait()

                try:
                    return imposta_interesse_annuncio(
                        conn, 10, 20, True, now=now
                    )
                finally:
                    conn.close()

            with ThreadPoolExecutor(max_workers=2) as executor:
                risultati = list(executor.map(lambda _: attiva(), range(2)))

            verifica_conn = sqlite3.connect(database_path)
            try:
                totale = verifica_conn.execute(
                    "SELECT COUNT(*) FROM interessi_annunci"
                ).fetchone()[0]
            finally:
                verifica_conn.close()

        self.assertEqual(
            sum(int(risultato["transizione"]) for risultato in risultati),
            1,
        )
        self.assertEqual(
            sum(int(risultato["notifica"]) for risultato in risultati),
            1,
        )
        self.assertEqual(totale, 1)

    def test_riattivazione_ravvicinata_non_rinotifica(self):
        now = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)
        imposta_interesse_annuncio(self.conn, 10, 20, True, now=now)
        off = imposta_interesse_annuncio(
            self.conn, 10, 20, False, now=now + timedelta(minutes=1)
        )
        on = imposta_interesse_annuncio(
            self.conn, 10, 20, True, now=now + timedelta(minutes=2)
        )

        self.assertTrue(off["transizione"])
        self.assertTrue(on["transizione"])
        self.assertFalse(on["notifica"])

        row = self.conn.execute(
            """
            SELECT attivo, disattivato_at, ultima_notifica_at
            FROM interessi_annunci
            WHERE annuncio_id = 10 AND utente_interessato_id = 20
            """
        ).fetchone()
        self.assertEqual(row["attivo"], 1)
        self.assertIsNone(row["disattivato_at"])
        self.assertEqual(
            row["ultima_notifica_at"],
            now.isoformat(timespec="microseconds"),
        )

    def test_riattivazione_dopo_cooldown_notifica(self):
        now = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)
        imposta_interesse_annuncio(self.conn, 10, 20, True, now=now)
        imposta_interesse_annuncio(
            self.conn, 10, 20, False, now=now + timedelta(minutes=1)
        )
        on = imposta_interesse_annuncio(
            self.conn,
            10,
            20,
            True,
            now=now + timedelta(hours=25),
        )

        self.assertTrue(on["transizione"])
        self.assertTrue(on["notifica"])

    def test_riattivazione_al_limite_di_24_ore_notifica(self):
        now = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)
        imposta_interesse_annuncio(self.conn, 10, 20, True, now=now)
        imposta_interesse_annuncio(
            self.conn, 10, 20, False, now=now + timedelta(minutes=1)
        )
        on = imposta_interesse_annuncio(
            self.conn,
            10,
            20,
            True,
            now=now + timedelta(hours=24),
        )

        self.assertTrue(on["transizione"])
        self.assertTrue(on["notifica"])

    def test_disattivazione_assente_non_crea_righe(self):
        result = imposta_interesse_annuncio(
            self.conn,
            99,
            42,
            False,
            now=datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc),
        )

        self.assertFalse(result["transizione"])
        self.assertFalse(result["attivo"])
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM interessi_annunci"
            ).fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
