import ast
import json
import re
import sqlite3
import unicodedata
import unittest
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace

from disponibilita_servizi import (
    CATEGORIE_SERVIZI,
    calcola_freschezza_disponibilita,
    normalize_disponibilita_payload,
    risolvi_disponibilita_per_categoria,
    serializza_disponibilita_pubblica,
)


ROOT = Path(__file__).resolve().parents[1]


def availability_payload(**overrides):
    payload = {
        "stato": "disponibile",
        "a_chiamata": False,
        "settimanale": [],
        "date_speciali": [],
        "assenze": [],
    }
    payload.update(overrides)
    return normalize_disponibilita_payload(payload)


def load_backend_functions():
    """Carica le funzioni pure/DB senza importare l'intera applicazione web."""

    wanted = {
        "to_slug",
        "_scheda_profilo_bool",
        "_disponibilita_servizi_table_exists",
        "_disponibilita_categoria_table_exists",
        "_disponibilita_servizi_iso",
        "_disponibilita_categoria_label",
        "_disponibilita_decode_slots",
        "_serializza_profilo_disponibilita",
        "carica_disponibilita_servizi",
        "carica_disponibilita_servizi_categoria",
        "elenca_disponibilita_servizi",
        "risolvi_disponibilita_servizi_annuncio",
        "_categorie_disponibilita_offerte",
        "_riepilogo_pubblico_disponibilita",
        "assegna_disponibilita_annunci",
        "_disponibilita_categoria_esistente",
        "_disponibilita_generale_esistente",
        "_valida_categoria_disponibilita_utente",
        "_elimina_disponibilita_generale",
        "_elimina_disponibilita_categoria",
        "_elimina_tutte_disponibilita_utente",
        "_salva_disponibilita_generale",
        "_salva_disponibilita_categoria",
        "_risposta_disponibilita_servizi",
    }
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    selected = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in wanted
    ]

    def fetchone_value(row):
        if row is None:
            return None
        if hasattr(row, "keys"):
            keys = list(row.keys())
            return row[keys[0]] if keys else None
        return row[0]

    def insert_and_get_id(cursor, query, params):
        cursor.execute(query, params)
        return cursor.lastrowid

    namespace = {
        "app": SimpleNamespace(config={"IS_POSTGRES": False}),
        "sql": lambda query: query,
        "fetchone_value": fetchone_value,
        "insert_and_get_id": insert_and_get_id,
        "json": json,
        "re": re,
        "unicodedata": unicodedata,
        "date": date,
        "datetime": datetime,
        "CATEGORY_MAP": {
            slug: (slug, slug.replace("-", " ").title())
            for slug in CATEGORIE_SERVIZI
        },
        "CATEGORIE_SERVIZI": CATEGORIE_SERVIZI,
        "calcola_freschezza_disponibilita": (
            calcola_freschezza_disponibilita
        ),
        "normalize_disponibilita_payload": normalize_disponibilita_payload,
        "risolvi_disponibilita_per_categoria": (
            risolvi_disponibilita_per_categoria
        ),
        "serializza_disponibilita_pubblica": (
            serializza_disponibilita_pubblica
        ),
    }
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    return namespace


class DisponibilitaBackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = load_backend_functions()

    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.cursor = self.connection.cursor()
        self.cursor.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                offro_1 INTEGER DEFAULT 0,
                offro_2 INTEGER DEFAULT 0,
                offro_3 INTEGER DEFAULT 0,
                offro_4 INTEGER DEFAULT 0,
                offro_5 INTEGER DEFAULT 0,
                offro_6 INTEGER DEFAULT 0,
                offro_7 INTEGER DEFAULT 0,
                offro_8 INTEGER DEFAULT 0,
                offro_9 INTEGER DEFAULT 0,
                offro_10 INTEGER DEFAULT 0,
                offro_11 INTEGER DEFAULT 0,
                offro_12 INTEGER DEFAULT 0,
                offro_13 INTEGER DEFAULT 0
            );
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria TEXT,
                tipo_annuncio TEXT,
                stato TEXT
            );
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                stato_generale TEXT NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                fuso_orario TEXT,
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE disponibilita_settimanale (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER,
                giorno_settimana INTEGER,
                fascia TEXT,
                created_at TEXT
            );
            CREATE TABLE disponibilita_date_speciali (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER,
                data TEXT,
                tipo TEXT,
                fasce TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE disponibilita_assenze (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER,
                data_inizio TEXT,
                data_fine TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                stato_generale TEXT NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                fuso_orario TEXT,
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                UNIQUE (utente_id, categoria_slug)
            );
            CREATE TABLE disponibilita_settimanale_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER,
                giorno_settimana INTEGER,
                fascia TEXT,
                created_at TEXT
            );
            CREATE TABLE disponibilita_date_speciali_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER,
                data TEXT,
                tipo TEXT,
                fasce TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE disponibilita_assenze_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER,
                data_inizio TEXT,
                data_fine TEXT,
                created_at TEXT,
                updated_at TEXT
            );
        """)

    def tearDown(self):
        self.connection.close()

    def test_salva_aggiorna_e_rilegge_disponibilita_categoria(self):
        save = self.backend["_salva_disponibilita_categoria"]
        load = self.backend["carica_disponibilita_servizi_categoria"]
        first = availability_payload(
            stato="limitata",
            a_chiamata=True,
            settimanale=[
                {"giorno_settimana": 2, "fascia": "pomeriggio"},
            ],
            date_speciali=[{
                "data": "2026-10-10",
                "tipo": "disponibile",
                "fasce": ["sera"],
            }],
            assenze=[{
                "data_inizio": "2026-12-20",
                "data_fine": "2026-12-27",
            }],
        )
        save(self.cursor, 7, "babysitter", first, 0)

        profile = load(self.cursor, 7, "babysitter", pubblica=False)
        self.assertEqual(profile["categoria_slug"], "babysitter")
        self.assertEqual(profile["stato"], "limitata")
        self.assertTrue(profile["a_chiamata"])
        self.assertEqual(profile["versione"], 1)
        self.assertEqual(profile["settimanale"], first["settimanale"])
        self.assertEqual(profile["date_speciali"], first["date_speciali"])
        self.assertEqual(profile["assenze"], first["assenze"])

        second = availability_payload(
            stato="disponibile",
            a_chiamata=False,
            settimanale=[
                {"giorno_settimana": 5, "fascia": "mattina"},
            ],
            date_speciali=[],
            assenze=[],
        )
        save(self.cursor, 7, "babysitter", second, 1)
        updated = load(self.cursor, 7, "babysitter", pubblica=False)
        self.assertEqual(updated["stato"], "disponibile")
        self.assertFalse(updated["a_chiamata"])
        self.assertEqual(updated["versione"], 2)
        self.assertEqual(updated["settimanale"], second["settimanale"])
        self.assertEqual(updated["date_speciali"], [])
        self.assertEqual(updated["assenze"], [])

    def test_salva_e_rilegge_a_chiamata_generale_senza_fasce(self):
        save = self.backend["_salva_disponibilita_generale"]
        load = self.backend["carica_disponibilita_servizi"]
        standalone = availability_payload(a_chiamata=True)

        save(self.cursor, 8, standalone, 0)

        private = load(self.cursor, 8, pubblica=False)
        public = load(self.cursor, 8, pubblica=True)
        stored = self.cursor.execute(
            "SELECT a_chiamata FROM disponibilita_profili "
            "WHERE utente_id = 8"
        ).fetchone()

        self.assertTrue(private["a_chiamata"])
        self.assertEqual(private["settimanale"], [])
        self.assertTrue(public["a_chiamata"])
        self.assertEqual(public["settimanale"], [])
        self.assertEqual(stored["a_chiamata"], 1)

    def test_payload_helper_disattiva_a_chiamata_per_default(self):
        self.assertFalse(availability_payload()["a_chiamata"])

    def test_card_offro_usa_categoria_e_fallback_generale(self):
        self.backend["_salva_disponibilita_generale"](
            self.cursor,
            7,
            availability_payload(a_chiamata=True),
            0,
        )
        self.backend["_salva_disponibilita_categoria"](
            self.cursor,
            7,
            "pet-sitter",
            availability_payload(stato="limitata", a_chiamata=False),
            0,
        )
        cards = [
            {
                "id": 1,
                "utente_id": 7,
                "tipo_annuncio": "offro",
                "categoria": "babysitter",
            },
            {
                "id": 2,
                "utente_id": 7,
                "tipo_annuncio": "OFFRO",
                "categoria": "pet-sitter",
            },
            {
                "id": 3,
                "utente_id": 7,
                "tipo_annuncio": "cerco",
                "categoria": "pet-sitter",
            },
        ]

        self.backend["assegna_disponibilita_annunci"](self.cursor, cards)

        self.assertEqual(cards[0]["disponibilita_servizi"]["stato"], "disponibile")
        self.assertTrue(cards[0]["disponibilita_servizi"]["a_chiamata"])
        self.assertIsNone(
            cards[0]["disponibilita_servizi"]["categoria_slug"]
        )
        self.assertEqual(cards[1]["disponibilita_servizi"]["stato"], "limitata")
        self.assertFalse(cards[1]["disponibilita_servizi"]["a_chiamata"])
        self.assertEqual(
            cards[1]["disponibilita_servizi"]["categoria_slug"],
            "pet-sitter",
        )
        self.assertNotIn("disponibilita_servizi", cards[2])

    def test_non_disponibile_conserva_calendario_privato_ma_non_pubblico(self):
        self.cursor.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at, versione
            ) VALUES (7, 'non_disponibile', CURRENT_TIMESTAMP, 1)
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_settimanale (
                utente_id, giorno_settimana, fascia
            ) VALUES (7, 1, 'mattina')
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_date_speciali (
                utente_id, data, tipo, fasce
            ) VALUES (7, '2026-10-10', 'disponibile', '["sera"]')
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_assenze (
                utente_id, data_inizio, data_fine
            ) VALUES (7, '2026-12-20', '2026-12-27')
        """)

        load = self.backend["carica_disponibilita_servizi"]
        private = load(self.cursor, 7, pubblica=False)
        public = load(self.cursor, 7, pubblica=True)

        self.assertEqual(len(private["settimanale"]), 1)
        self.assertEqual(len(private["date_speciali"]), 1)
        self.assertEqual(len(private["assenze"]), 1)
        self.assertEqual(public["stato"], "non_disponibile")
        self.assertEqual(public["settimanale"], [])
        self.assertEqual(public["date_speciali"], [])
        self.assertEqual(public["assenze"], [])

    def test_elimina_override_e_ripristina_fallback_generale(self):
        self.cursor.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at, versione
            ) VALUES (7, 'disponibile', CURRENT_TIMESTAMP, 1)
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_profili_categoria (
                id, utente_id, categoria_slug, stato_generale,
                confermata_at, versione
            ) VALUES (12, 7, 'pet-sitter', 'limitata', CURRENT_TIMESTAMP, 2)
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_settimanale_categoria (
                profilo_categoria_id, giorno_settimana, fascia
            ) VALUES (12, 2, 'pomeriggio')
        """)

        deleted = self.backend["_elimina_disponibilita_categoria"](
            self.cursor,
            7,
            "pet-sitter",
            submitted_version=2,
        )
        resolved = self.backend["risolvi_disponibilita_servizi_annuncio"](
            self.cursor,
            7,
            "pet-sitter",
            pubblica=False,
        )

        self.assertTrue(deleted)
        self.assertIsNone(resolved["categoria_slug"])
        self.assertEqual(resolved["stato"], "disponibile")
        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) FROM disponibilita_profili_categoria"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) FROM disponibilita_settimanale_categoria"
            ).fetchone()[0],
            0,
        )

    def test_elimina_generale_rimuove_anche_i_figli_diretti(self):
        self.cursor.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at, versione
            ) VALUES (7, 'disponibile', CURRENT_TIMESTAMP, 3)
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_settimanale (
                utente_id, giorno_settimana, fascia
            ) VALUES (7, 1, 'mattina')
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_date_speciali (
                utente_id, data, tipo, fasce
            ) VALUES (7, '2026-10-10', 'non_disponibile', '[]')
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_assenze (
                utente_id, data_inizio, data_fine
            ) VALUES (7, '2026-12-20', '2026-12-27')
        """)

        deleted = self.backend["_elimina_disponibilita_generale"](
            self.cursor,
            7,
            submitted_version=3,
        )

        self.assertTrue(deleted)
        for table in (
            "disponibilita_profili",
            "disponibilita_settimanale",
            "disponibilita_date_speciali",
            "disponibilita_assenze",
        ):
            count = self.cursor.execute(
                f"SELECT COUNT(*) FROM {table} WHERE utente_id = 7"
            ).fetchone()[0]
            self.assertEqual(count, 0, table)

    def test_bonifica_figli_generali_anche_se_il_parent_manca(self):
        self.cursor.execute("""
            INSERT INTO disponibilita_settimanale (
                utente_id, giorno_settimana, fascia
            ) VALUES (7, 1, 'mattina')
        """)

        deleted = self.backend["_elimina_disponibilita_generale"](
            self.cursor,
            7,
        )

        self.assertFalse(deleted)
        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) FROM disponibilita_settimanale"
            ).fetchone()[0],
            0,
        )

    def test_anonimizzazione_bonifica_generale_e_categorie(self):
        self.cursor.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, versione
            ) VALUES (7, 'disponibile', 1)
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_settimanale (
                utente_id, giorno_settimana, fascia
            ) VALUES (7, 1, 'mattina')
        """)
        self.cursor.execute("""
            INSERT INTO disponibilita_profili_categoria (
                id, utente_id, categoria_slug, stato_generale, versione
            ) VALUES (12, 7, 'babysitter', 'limitata', 1)
        """)

        self.backend["_elimina_tutte_disponibilita_utente"](
            self.cursor,
            7,
        )

        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) FROM disponibilita_profili"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) FROM disponibilita_settimanale"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) FROM disponibilita_profili_categoria"
            ).fetchone()[0],
            0,
        )

    def test_primo_salvataggio_generale_richiede_un_servizio_offerto(self):
        validate = self.backend["_valida_categoria_disponibilita_utente"]
        self.cursor.execute("INSERT INTO utenti (id) VALUES (1)")
        with self.assertRaisesRegex(ValueError, "offri almeno un servizio"):
            validate(self.cursor, 1, None)

        self.cursor.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, versione
            ) VALUES (1, 'disponibile', 1)
        """)
        validate(self.cursor, 1, None)

        self.cursor.execute("""
            INSERT INTO utenti (id, offro_4) VALUES (2, 1)
        """)
        validate(self.cursor, 2, None)

    def test_pubblico_esclude_override_di_categoria_non_piu_offerta(self):
        self.cursor.execute("""
            INSERT INTO utenti (id, offro_4) VALUES (7, 1)
        """)
        self.cursor.executemany("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale, versione
            ) VALUES (7, ?, 'disponibile', 1)
        """, [("babysitter",), ("pet-sitter",)])

        list_profiles = self.backend["elenca_disponibilita_servizi"]
        private = list_profiles(self.cursor, 7, pubblica=False)
        public = list_profiles(self.cursor, 7, pubblica=True)

        self.assertEqual(
            {item["categoria_slug"] for item in private},
            {"babysitter", "pet-sitter"},
        )
        self.assertEqual(
            {item["categoria_slug"] for item in public},
            {"babysitter"},
        )

    def test_risposta_rollout_senza_tabelle_categoria(self):
        self.cursor.execute("""
            INSERT INTO utenti (id, offro_4) VALUES (7, 1)
        """)
        self.cursor.execute("DROP TABLE disponibilita_assenze_categoria")
        self.cursor.execute("DROP TABLE disponibilita_date_speciali_categoria")
        self.cursor.execute("DROP TABLE disponibilita_settimanale_categoria")
        self.cursor.execute("DROP TABLE disponibilita_profili_categoria")

        response = self.backend["_risposta_disponibilita_servizi"](
            self.cursor,
            7,
        )

        self.assertFalse(response["scope_categoria_disponibile"])
        self.assertEqual(response["categorie_offerte"], [])
        self.assertTrue(response["utente_offre_servizi"])


if __name__ == "__main__":
    unittest.main()
