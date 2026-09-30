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


def load_app_function(function_name, namespace):
    """Carica una singola route senza avviare l'intera applicazione."""

    source = (ROOT / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    function.decorator_list = []
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    return namespace[function_name]


def load_backend_functions():
    """Carica le funzioni pure/DB senza importare l'intera applicazione web."""

    wanted = {
        "to_slug",
        "_scheda_profilo_bool",
        "_disponibilita_servizi_table_exists",
        "_disponibilita_categoria_table_exists",
        "_disponibilita_intervalli_table_exists",
        "_annunci_disponibilita_ciclo_tables_exist",
        "_disponibilita_servizi_iso",
        "_disponibilita_servizi_time",
        "_disponibilita_categoria_label",
        "_disponibilita_decode_slots",
        "_serializza_profilo_disponibilita",
        "carica_disponibilita_servizi",
        "carica_disponibilita_servizi_categoria",
        "elenca_disponibilita_servizi",
        "risolvi_disponibilita_servizi_annuncio",
        "_categorie_disponibilita_offerte",
        "_categorie_annunci_disponibilita_rilevanti",
        "_annunci_attivi_disponibilita_categoria",
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
                titolo TEXT,
                categoria TEXT,
                tipo_annuncio TEXT,
                stato TEXT,
                media TEXT,
                foto_card TEXT
            );
            CREATE TABLE interessi_annunci (
                id INTEGER PRIMARY KEY,
                annuncio_id INTEGER NOT NULL,
                attivo INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT,
                disattivato_at TEXT
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
            CREATE TABLE disponibilita_intervalli (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER,
                giorno_settimana INTEGER,
                ora_inizio TEXT,
                ora_fine TEXT,
                giorno_successivo INTEGER DEFAULT 0,
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
            CREATE TABLE disponibilita_intervalli_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER,
                giorno_settimana INTEGER,
                ora_inizio TEXT,
                ora_fine TEXT,
                giorno_successivo INTEGER DEFAULT 0,
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

    def test_aggiornamento_compatto_conserva_date_speciali_e_assenze(self):
        save = self.backend["_salva_disponibilita_categoria"]
        load = self.backend["carica_disponibilita_servizi_categoria"]
        existing = availability_payload(
            stato="limitata",
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
        save(self.cursor, 71, "babysitter", existing, 0)

        compact_update = availability_payload(
            stato="disponibile",
            a_chiamata=True,
            settimanale=[
                {"giorno_settimana": 5, "fascia": "mattina"},
            ],
            settimanale_intervalli=[{
                "giorno_settimana": 5,
                "ora_inizio": "09:00",
                "ora_fine": "12:00",
                "giorno_successivo": False,
            }],
            date_speciali=[],
            assenze=[],
        )
        save(
            self.cursor,
            71,
            "babysitter",
            compact_update,
            1,
            preserve_calendar_exceptions=True,
        )

        updated = load(self.cursor, 71, "babysitter", pubblica=False)
        self.assertEqual(updated["versione"], 2)
        self.assertTrue(updated["a_chiamata"])
        self.assertEqual(updated["settimanale"], compact_update["settimanale"])
        self.assertEqual(
            updated["settimanale_intervalli"],
            compact_update["settimanale_intervalli"],
        )
        self.assertEqual(updated["date_speciali"], existing["date_speciali"])
        self.assertEqual(updated["assenze"], existing["assenze"])

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

    def test_intervalli_precisi_round_trip_generale_categoria_e_pubblico(self):
        save_general = self.backend["_salva_disponibilita_generale"]
        load_general = self.backend["carica_disponibilita_servizi"]
        save_category = self.backend["_salva_disponibilita_categoria"]
        load_category = self.backend["carica_disponibilita_servizi_categoria"]

        general_intervals = [
            {
                "giorno_settimana": 1,
                "ora_inizio": "09:15",
                "ora_fine": "12:30",
                "giorno_successivo": False,
            },
            {
                "giorno_settimana": 5,
                "ora_inizio": "22:00",
                "ora_fine": "02:00",
                "giorno_successivo": True,
            },
        ]
        category_intervals = [
            {
                "giorno_settimana": 2,
                "ora_inizio": "13:00",
                "ora_fine": "16:45",
                "giorno_successivo": False,
            },
        ]

        save_general(
            self.cursor,
            21,
            availability_payload(
                a_chiamata=True,
                settimanale_intervalli=general_intervals,
            ),
            0,
        )
        save_category(
            self.cursor,
            21,
            "babysitter",
            availability_payload(
                stato="limitata",
                settimanale_intervalli=category_intervals,
            ),
            0,
        )

        general_private = load_general(self.cursor, 21, pubblica=False)
        general_public = load_general(self.cursor, 21, pubblica=True)
        category_private = load_category(
            self.cursor,
            21,
            "babysitter",
            pubblica=False,
        )
        category_public = load_category(
            self.cursor,
            21,
            "babysitter",
            pubblica=True,
        )

        self.assertEqual(
            general_private["settimanale_intervalli"],
            general_intervals,
        )
        self.assertEqual(
            general_public["settimanale_intervalli"],
            general_intervals,
        )
        self.assertEqual(
            category_private["settimanale_intervalli"],
            category_intervals,
        )
        self.assertEqual(
            category_public["settimanale_intervalli"],
            category_intervals,
        )
        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) FROM disponibilita_intervalli "
                "WHERE utente_id = 21"
            ).fetchone()[0],
            2,
        )
        self.assertEqual(
            self.cursor.execute(
                "SELECT COUNT(*) "
                "FROM disponibilita_intervalli_categoria dic "
                "JOIN disponibilita_profili_categoria dpc "
                "ON dpc.id = dic.profilo_categoria_id "
                "WHERE dpc.utente_id = 21 "
                "AND dpc.categoria_slug = 'babysitter'"
            ).fetchone()[0],
            1,
        )

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

    def test_scadenza_non_confonde_non_disponibilita_volontaria(self):
        self.cursor.executemany("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at, versione
            ) VALUES (?, ?, '2020-01-01T00:00:00+00:00', 1)
        """, [
            (70, "disponibile"),
            (71, "non_disponibile"),
        ])
        cards = [
            {
                "id": 170,
                "utente_id": 70,
                "tipo_annuncio": "offro",
                "categoria": "babysitter",
            },
            {
                "id": 171,
                "utente_id": 71,
                "tipo_annuncio": "offro",
                "categoria": "babysitter",
            },
        ]

        self.backend["assegna_disponibilita_annunci"](self.cursor, cards)

        expired = cards[0]["disponibilita_servizi"]
        voluntary = cards[1]["disponibilita_servizi"]
        self.assertEqual(expired["stato"], "non_disponibile")
        self.assertTrue(expired["non_disponibile_per_scadenza"])
        self.assertEqual(voluntary["stato"], "non_disponibile")
        self.assertNotIn("non_disponibile_per_scadenza", voluntary)

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

    def test_annunci_attivi_categoria_esclude_altri_utenti_e_stati(self):
        self.cursor.executemany("""
            INSERT INTO annunci (
                id, utente_id, titolo, categoria, tipo_annuncio, stato
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, [
            (1, 7, "Babysitter serale", "Babysitter", "offro", "approvato"),
            (2, 7, "Aiuto weekend", "babysitter", "offro", "approvato"),
            (3, 7, "Cerco babysitter", "babysitter", "cerco", "approvato"),
            (4, 7, "In attesa", "babysitter", "offro", "in_attesa"),
            (5, 8, "Di un altro utente", "babysitter", "offro", "approvato"),
            (6, 7, "Pet sitter", "pet-sitter", "offro", "approvato"),
        ])

        listings = self.backend[
            "_annunci_attivi_disponibilita_categoria"
        ](self.cursor, 7, "BABYSITTER")

        self.assertEqual([item["id"] for item in listings], [2, 1])
        self.assertEqual(
            [item["titolo"] for item in listings],
            ["Aiuto weekend", "Babysitter serale"],
        )
        self.assertTrue(all(
            item["categoria_slug"] == "babysitter"
            for item in listings
        ))

    def test_risposta_generale_non_propone_cancellazioni_annunci(self):
        self.cursor.execute("INSERT INTO utenti (id, offro_4) VALUES (7, 1)")
        self.cursor.execute("""
            INSERT INTO annunci (
                id, utente_id, titolo, categoria, tipo_annuncio, stato
            ) VALUES (1, 7, 'Babysitter serale', 'babysitter', 'offro', 'approvato')
        """)

        response = self.backend["_risposta_disponibilita_servizi"](
            self.cursor,
            7,
        )

        self.assertEqual(response["annunci_attivi_categoria"], [])

    def test_risposta_categoria_propone_solo_annunci_attivi_dell_ambito(self):
        self.cursor.execute("INSERT INTO utenti (id, offro_4) VALUES (7, 1)")
        self.cursor.executemany("""
            INSERT INTO annunci (
                id, utente_id, titolo, categoria, tipo_annuncio, stato
            ) VALUES (?, 7, ?, ?, 'offro', ?)
        """, [
            (1, "Babysitter serale", "babysitter", "approvato"),
            (2, "Pet sitter", "pet-sitter", "approvato"),
            (3, "Vecchio annuncio", "babysitter", "eliminato"),
        ])

        response = self.backend["_risposta_disponibilita_servizi"](
            self.cursor,
            7,
            categoria_slug="babysitter",
        )

        self.assertEqual(
            response["annunci_attivi_categoria"],
            [{
                "id": 1,
                "titolo": "Babysitter serale",
                "categoria_slug": "babysitter",
            }],
        )

    def test_endpoint_elimina_solo_annuncio_attivo_del_proprietario(self):
        self.cursor.executemany("""
            INSERT INTO annunci (
                id, utente_id, titolo, categoria, tipo_annuncio, stato,
                media, foto_card
            ) VALUES (?, ?, ?, 'babysitter', 'offro', ?, ?, ?)
        """, [
            (1, 7, "Babysitter serale", "approvato", "a.jpg,b.jpg", "a.jpg"),
            (2, 7, "Secondo annuncio", "approvato", "c.jpg", "c.jpg"),
            (3, 8, "Annuncio altrui", "approvato", "d.jpg", "d.jpg"),
        ])
        self.cursor.execute(
            "INSERT INTO interessi_annunci (id, annuncio_id) VALUES (10, 1)"
        )
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

        csrf_calls = []
        deleted_paths = []
        invalidations = []
        namespace = {
            "g": SimpleNamespace(utente={"id": 7}),
            "verify_csrf": lambda: csrf_calls.append(True),
            "get_db_connection": lambda: NonClosingConnection(self.connection),
            "get_cursor": lambda connection: connection.cursor(),
            "sql": lambda query: query,
            "now_sql": lambda: "CURRENT_TIMESTAMP",
            "jsonify": lambda payload: payload,
            "log_exception_safe": lambda *args, **kwargs: None,
            "elimina_percorsi_immagine_locale": (
                lambda paths: deleted_paths.extend(paths)
            ),
            "invalidate_admin_counters": lambda: invalidations.append(True),
            "app": SimpleNamespace(
                logger=SimpleNamespace(warning=lambda *args, **kwargs: None)
            ),
        }
        route = load_app_function("elimina_annuncio_api", namespace)

        response = route(1)

        self.assertEqual(response["ok"], True)
        self.assertEqual(response["annuncio_id"], 1)
        self.assertEqual(csrf_calls, [True])
        self.assertEqual(deleted_paths, ["a.jpg", "b.jpg"])
        self.assertEqual(invalidations, [True])
        deleted = self.cursor.execute(
            "SELECT stato, media, foto_card FROM annunci WHERE id = 1"
        ).fetchone()
        untouched = self.cursor.execute(
            "SELECT stato, media FROM annunci WHERE id = 2"
        ).fetchone()
        interest = self.cursor.execute(
            "SELECT attivo FROM interessi_annunci WHERE id = 10"
        ).fetchone()
        self.assertEqual(dict(deleted), {
            "stato": "eliminato",
            "media": "",
            "foto_card": None,
        })
        self.assertEqual(dict(untouched), {
            "stato": "approvato",
            "media": "c.jpg",
        })
        self.assertEqual(interest["attivo"], 0)

        foreign_response, status = route(3)
        self.assertEqual(status, 404)
        self.assertFalse(foreign_response["ok"])
        self.assertEqual(
            self.cursor.execute(
                "SELECT stato FROM annunci WHERE id = 3"
            ).fetchone()["stato"],
            "approvato",
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
