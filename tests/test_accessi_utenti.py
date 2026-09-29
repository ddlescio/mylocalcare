import ast
import copy
import sqlite3
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from accessi_utenti import (
    ACCESS_WINDOW_DAYS,
    carica_statistiche_accessi,
    elimina_accessi_utente,
    elimina_accessi_scaduti,
    giorno_locale,
    normalizza_zona,
    registra_accesso_giornaliero,
)


SCHEMA = """
CREATE TABLE accessi_utenti_giornalieri (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    utente_id INTEGER NOT NULL,
    giorno TEXT NOT NULL,
    zona TEXT NOT NULL,
    primo_accesso_at TEXT NOT NULL,
    ultimo_accesso_at TEXT NOT NULL,
    UNIQUE (utente_id, giorno)
)
"""


class AccessiUtentiTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(SCHEMA)

    def tearDown(self):
        self.conn.close()

    def test_un_solo_accesso_per_utente_e_giorno(self):
        giorno = date(2026, 9, 29)
        registra_accesso_giornaliero(
            self.conn,
            utente_id=7,
            zona="Milano",
            giorno=giorno,
            istante=datetime(2026, 9, 29, 8, 0),
        )
        registra_accesso_giornaliero(
            self.conn,
            utente_id=7,
            zona="Milano",
            giorno=giorno,
            istante=datetime(2026, 9, 29, 18, 0),
        )

        rows = self.conn.execute(
            "SELECT * FROM accessi_utenti_giornalieri"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIn("18:00:00", rows[0]["ultimo_accesso_at"])

    def test_retention_elimina_tutto_oltre_trenta_giorni(self):
        oggi = date(2026, 9, 29)
        self.conn.executemany(
            """
            INSERT INTO accessi_utenti_giornalieri (
                utente_id, giorno, zona, primo_accesso_at, ultimo_accesso_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (1, (oggi - timedelta(days=30)).isoformat(), "Roma", "x", "x"),
                (2, (oggi - timedelta(days=29)).isoformat(), "Milano", "x", "x"),
            ],
        )
        self.conn.commit()

        self.assertEqual(elimina_accessi_scaduti(self.conn, giorno=oggi), 1)
        rimasto = self.conn.execute(
            "SELECT utente_id FROM accessi_utenti_giornalieri"
        ).fetchone()[0]
        self.assertEqual(rimasto, 2)

    def test_metriche_grafico_e_percentuali_zone(self):
        oggi = date(2026, 9, 29)
        dati = [
            (1, oggi, "Milano"),
            (2, oggi, "Roma"),
            (1, oggi - timedelta(days=2), "Milano"),
            (3, oggi - timedelta(days=8), "Milano"),
        ]
        for utente_id, giorno, zona in dati:
            registra_accesso_giornaliero(
                self.conn,
                utente_id=utente_id,
                zona=zona,
                giorno=giorno,
            )

        statistiche = carica_statistiche_accessi(self.conn, giorno=oggi)

        self.assertEqual(statistiche["oggi"], 2)
        self.assertEqual(statistiche["settimana"], 2)
        self.assertEqual(statistiche["mese"], 3)
        self.assertEqual(len(statistiche["serie"]), ACCESS_WINDOW_DAYS)
        self.assertEqual(statistiche["serie"][-1]["valore"], 2)
        self.assertEqual(statistiche["zone"][0]["nome"], "Milano")
        self.assertEqual(statistiche["zone"][0]["percentuale"], 66.7)

    def test_giorno_locale_rispetta_il_confine_italiano(self):
        utc = ZoneInfo("UTC")
        self.assertEqual(
            giorno_locale(datetime(2026, 9, 29, 22, 30, tzinfo=utc)),
            date(2026, 9, 30),
        )

    def test_zona_non_usa_valori_vuoti(self):
        self.assertEqual(
            normalizza_zona("", None, "Torino"),
            "Torino",
        )

    def test_eliminazione_account_purga_le_presenze_senza_commit_autonomo(self):
        self.conn.execute(
            """
            INSERT INTO accessi_utenti_giornalieri (
                utente_id, giorno, zona, primo_accesso_at, ultimo_accesso_at
            ) VALUES (7, '2026-09-29', 'Milano', 'x', 'x')
            """
        )
        self.conn.commit()

        self.assertEqual(
            elimina_accessi_utente(self.conn.cursor(), 7, postgres=False),
            1,
        )
        self.conn.rollback()
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM accessi_utenti_giornalieri WHERE utente_id = 7"
            ).fetchone()[0],
            1,
        )

    def test_eliminazione_account_prima_della_migrazione_e_un_noop(self):
        conn = sqlite3.connect(":memory:")
        try:
            self.assertEqual(
                elimina_accessi_utente(conn.cursor(), 7, postgres=False),
                0,
            )
        finally:
            conn.close()


class AccessiUtentiIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.app_source = (cls.root / "app.py").read_text(encoding="utf-8")

        tree = ast.parse(cls.app_source)
        node = next(
            item
            for item in tree.body
            if isinstance(item, ast.FunctionDef)
            and item.name == "_registra_accesso_utente_corrente"
        )
        module = ast.fix_missing_locations(
            ast.Module(body=[copy.deepcopy(node)], type_ignores=[])
        )
        cls.function_code = compile(module, str(cls.root / "app.py"), "exec")

    def build_function(self, user):
        calls = []
        session = {}
        app = SimpleNamespace(config={})
        namespace = {
            "g": SimpleNamespace(utente=user),
            "session": session,
            "app": app,
            "time": SimpleNamespace(monotonic=lambda: 100.0),
            "giorno_locale_accessi": lambda: date(2026, 9, 29),
            "normalizza_zona_accessi": normalizza_zona,
            "registra_accesso_giornaliero": (
                lambda conn, **kwargs: calls.append(kwargs)
            ),
            "log_exception_safe": lambda *args, **kwargs: None,
        }
        exec(self.function_code, namespace)
        return namespace["_registra_accesso_utente_corrente"], session, calls

    def test_hook_registra_una_sola_volta_e_preferisce_la_citta(self):
        function, session, calls = self.build_function({
            "id": 7,
            "ruolo": "user",
            "citta": "Milano",
            "provincia": "MI",
            "regione": "Lombardia",
        })

        function(object())
        function(object())

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["zona"], "Milano")
        self.assertEqual(session["_accesso_giornaliero"], "7:2026-09-29")

    def test_hook_non_registra_amministratori(self):
        function, session, calls = self.build_function({
            "id": 1,
            "ruolo": "admin",
            "citta": "Milano",
            "provincia": "MI",
            "regione": "Lombardia",
        })

        function(object())

        self.assertEqual(calls, [])
        self.assertEqual(session, {})

    def test_migration_minimizza_dati_e_cancella_con_account(self):
        migration = (
            self.root
            / "migrations"
            / "20260929_accessi_utenti_giornalieri.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("UNIQUE (utente_id, giorno)", migration)
        self.assertIn("REFERENCES utenti(id) ON DELETE CASCADE", migration)
        for forbidden in ("ip_address", "user_agent", "pagina_visitata"):
            self.assertNotIn(forbidden, migration.lower())

    def test_app_non_sovrascrive_il_modulo_time_con_la_funzione_time(self):
        self.assertIn("import time", self.app_source)
        self.assertNotIn("from time import time", self.app_source)
        self.assertIn("time.monotonic()", self.app_source)

    def test_privacy_policy_discloses_scope_and_retention(self):
        privacy = (self.root / "templates" / "privacy.html").read_text(
            encoding="utf-8"
        )
        for marker in (
            "una sola presenza giornaliera",
            "non riguarda i visitatori anonimi",
            "non più di 30 giorni",
            "eliminate insieme all’account",
            "distribuzioni territoriali aggregate",
            "analisi interna minimizzata",
        ):
            self.assertIn(marker, privacy)

    def test_both_account_deletion_flows_purge_access_rows(self):
        models_source = (self.root / "models.py").read_text(encoding="utf-8")
        self.assertIn("elimina_accessi_utente(", self.app_source)
        self.assertIn("elimina_accessi_utente(", models_source)


if __name__ == "__main__":
    unittest.main()
