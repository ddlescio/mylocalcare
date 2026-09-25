import importlib.util
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_init_db_without_flask():
    fake_app_module = types.ModuleType("app")
    fake_app_module.app = object()
    fake_app_module.sql = lambda query: query
    fake_app_module.now_sql = lambda: "CURRENT_TIMESTAMP"

    module_name = "init_db_disponibilita_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "init_db.py",
    )
    module = importlib.util.module_from_spec(spec)
    original_directory = Path.cwd()
    with tempfile.TemporaryDirectory() as isolated_directory:
        try:
            os.chdir(isolated_directory)
            with mock.patch.dict(
                sys.modules,
                {"app": fake_app_module, module_name: module},
            ), mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DATABASE_URL", None)
                spec.loader.exec_module(module)
        finally:
            os.chdir(original_directory)
    return module


class DisponibilitaSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.init_db = load_init_db_without_flask()

    def setUp(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        self.database_path = Path(temporary.name)
        connection = self._connect()
        connection.execute("CREATE TABLE utenti (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO utenti (id) VALUES (1)")
        connection.commit()
        connection.close()

    def tearDown(self):
        self.database_path.unlink(missing_ok=True)

    def _connect(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _bootstrap(self):
        with mock.patch.object(
            self.init_db,
            "get_conn",
            side_effect=self._connect,
        ):
            self.init_db.crea_tabelle_disponibilita_servizi()

    def test_bootstrap_e_idempotente_e_crea_le_otto_tabelle(self):
        self._bootstrap()
        self._bootstrap()
        connection = self._connect()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        connection.close()
        self.assertTrue({
            "disponibilita_profili",
            "disponibilita_settimanale",
            "disponibilita_date_speciali",
            "disponibilita_assenze",
            "disponibilita_profili_categoria",
            "disponibilita_settimanale_categoria",
            "disponibilita_date_speciali_categoria",
            "disponibilita_assenze_categoria",
        }.issubset(tables))

    def test_vincoli_e_cancellazione_in_cascata(self):
        self._bootstrap()
        connection = self._connect()
        connection.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at,
                created_at, updated_at
            ) VALUES (1, 'disponibile', CURRENT_TIMESTAMP,
                      CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """)
        connection.execute("""
            INSERT INTO disponibilita_settimanale (
                utente_id, giorno_settimana, fascia, created_at
            ) VALUES (1, 1, 'mattina', CURRENT_TIMESTAMP)
        """)
        connection.execute("""
            INSERT INTO disponibilita_date_speciali (
                utente_id, data, tipo, fasce, created_at, updated_at
            ) VALUES (1, '2026-10-01', 'disponibile', '["mattina"]',
                      CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """)
        connection.execute("""
            INSERT INTO disponibilita_assenze (
                utente_id, data_inizio, data_fine, created_at, updated_at
            ) VALUES (1, '2026-12-20', '2026-12-27',
                      CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """)
        cursor = connection.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale,
                created_at, updated_at
            ) VALUES (1, 'babysitter', 'limitata',
                      CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """)
        profile_id = cursor.lastrowid
        connection.execute("""
            INSERT INTO disponibilita_settimanale_categoria (
                profilo_categoria_id, giorno_settimana, fascia, created_at
            ) VALUES (?, 2, 'pomeriggio', CURRENT_TIMESTAMP)
        """, (profile_id,))
        connection.execute("""
            INSERT INTO disponibilita_date_speciali_categoria (
                profilo_categoria_id, data, tipo, fasce,
                created_at, updated_at
            ) VALUES (?, '2026-11-01', 'disponibile', '["sera"]',
                      CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (profile_id,))
        connection.execute("""
            INSERT INTO disponibilita_assenze_categoria (
                profilo_categoria_id, data_inizio, data_fine,
                created_at, updated_at
            ) VALUES (?, '2027-01-01', '2027-01-07',
                      CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (profile_id,))

        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO disponibilita_settimanale (
                    utente_id, giorno_settimana, fascia, created_at
                ) VALUES (1, 1, 'mattina', CURRENT_TIMESTAMP)
            """)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO disponibilita_date_speciali (
                    utente_id, data, tipo, fasce, created_at, updated_at
                ) VALUES (1, '2026-10-01', 'non_disponibile', '[]',
                          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO disponibilita_assenze (
                    utente_id, data_inizio, data_fine,
                    created_at, updated_at
                ) VALUES (1, '2026-12-31', '2026-12-01',
                          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO disponibilita_profili_categoria (
                    utente_id, categoria_slug, created_at, updated_at
                ) VALUES (1, 'babysitter', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("""
                INSERT INTO disponibilita_profili_categoria (
                    utente_id, categoria_slug, created_at, updated_at
                ) VALUES (1, 'categoria-inventata',
                          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """)

        connection.execute("DELETE FROM utenti WHERE id = 1")
        for table in (
            "disponibilita_profili",
            "disponibilita_settimanale",
            "disponibilita_date_speciali",
            "disponibilita_assenze",
            "disponibilita_profili_categoria",
            "disponibilita_settimanale_categoria",
            "disponibilita_date_speciali_categoria",
            "disponibilita_assenze_categoria",
        ):
            total = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            self.assertEqual(total, 0, table)
        connection.close()

    def test_migrazione_postgres_include_permessi_e_indici_univoci(self):
        migration = (
            ROOT / "migrations" / "20260925_disponibilita_servizi.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("GRANT SELECT, INSERT, UPDATE, DELETE", migration)
        self.assertIn("TO localcare_app", migration)
        self.assertIn("ux_disponibilita_date_utente", migration)
        self.assertIn("ux_disponibilita_assenze_utente", migration)
        self.assertIn("disponibilita_profili_categoria", migration)

        additive = (
            ROOT / "migrations" / "20260925_disponibilita_per_categoria.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("disponibilita_profili_categoria", additive)
        self.assertIn("TO localcare_app", additive)
        self.assertNotIn("DROP TABLE", additive.upper())
        self.assertNotIn("ALTER TABLE disponibilita_profili", additive)

        on_call = (
            ROOT / "migrations" / "20260925_disponibilita_a_chiamata.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("ALTER TABLE disponibilita_profili", on_call)
        self.assertIn("ALTER TABLE disponibilita_profili_categoria", on_call)
        self.assertIn("a_chiamata BOOLEAN NOT NULL DEFAULT FALSE", on_call)
        self.assertNotIn("DROP TABLE", on_call.upper())

    def test_bootstrap_include_opzione_a_chiamata(self):
        self._bootstrap()
        connection = self._connect()
        general_columns = {
            row[1]: row for row in connection.execute(
                "PRAGMA table_info(disponibilita_profili)"
            )
        }
        category_columns = {
            row[1]: row for row in connection.execute(
                "PRAGMA table_info(disponibilita_profili_categoria)"
            )
        }
        connection.close()

        self.assertIn("a_chiamata", general_columns)
        self.assertIn("a_chiamata", category_columns)
        self.assertEqual(general_columns["a_chiamata"][3], 1)
        self.assertEqual(category_columns["a_chiamata"][3], 1)

    def test_bootstrap_aggiunge_a_chiamata_a_tabelle_esistenti(self):
        connection = self._connect()
        connection.executescript("""
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                stato_generale TEXT NOT NULL DEFAULT 'disponibile',
                fuso_orario TEXT,
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                stato_generale TEXT NOT NULL DEFAULT 'disponibile',
                fuso_orario TEXT,
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                UNIQUE (utente_id, categoria_slug)
            );
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, versione
            ) VALUES (1, 'limitata', 3);
        """)
        connection.commit()
        connection.close()

        self._bootstrap()

        connection = self._connect()
        profile = connection.execute(
            "SELECT stato_generale, versione, a_chiamata "
            "FROM disponibilita_profili WHERE utente_id = 1"
        ).fetchone()
        category_columns = {
            row[1] for row in connection.execute(
                "PRAGMA table_info(disponibilita_profili_categoria)"
            )
        }
        connection.close()

        self.assertEqual(profile["stato_generale"], "limitata")
        self.assertEqual(profile["versione"], 3)
        self.assertEqual(profile["a_chiamata"], 0)
        self.assertIn("a_chiamata", category_columns)


if __name__ == "__main__":
    unittest.main()
