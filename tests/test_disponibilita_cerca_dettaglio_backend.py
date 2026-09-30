import ast
import re
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from disponibilita_servizi import (
    GIORNI_ESCLUSIONE_FILTRO,
    GIORNI_PRIORITA_RIDOTTA,
)


ROOT = Path(__file__).resolve().parents[1]


class MultiArgs:
    """Sostituto minimo di MultiDict per testare parametri GET ripetuti."""

    def __init__(self, values=None):
        self.values = dict(values or {})

    def getlist(self, name):
        value = self.values.get(name, [])
        return list(value) if isinstance(value, (list, tuple)) else [value]

    def get(self, name, default=None):
        value = self.values.get(name, default)
        if isinstance(value, (list, tuple)):
            return value[0] if value else default
        return value


def load_search_backend():
    wanted = {
        "_disponibilita_intervalli_table_exists",
        "_normalizza_filtri_disponibilita_cerca",
        "_disponibilita_profilo_schedule_sql",
        "_disponibilita_filtro_cerca_sql",
    }
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    namespace = {
        "app": SimpleNamespace(config={"IS_POSTGRES": False}),
        "sql": lambda query: query,
        "fetchone_value": lambda row: row[0] if row else None,
        "re": re,
        "GIORNI_ESCLUSIONE_FILTRO": GIORNI_ESCLUSIONE_FILTRO,
        "GIORNI_PRIORITA_RIDOTTA": GIORNI_PRIORITA_RIDOTTA,
        "_DISPONIBILITA_CERCA_HHMM_RE": re.compile(
            r"^(?:[01]\d|2[0-3]):[0-5]\d$"
        ),
    }
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    namespace.update({
        "_disponibilita_servizi_table_exists": lambda cur: True,
        "_disponibilita_categoria_table_exists": lambda cur: True,
    })
    return namespace


class DisponibilitaCercaDettaglioBackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = load_search_backend()

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                tipo_annuncio TEXT,
                categoria TEXT NOT NULL
            );
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                stato_generale TEXT NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                confermata_at TEXT
            );
            CREATE TABLE disponibilita_settimanale (
                utente_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                fascia TEXT NOT NULL
            );
            CREATE TABLE disponibilita_intervalli (
                utente_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                ora_inizio TEXT NOT NULL,
                ora_fine TEXT NOT NULL,
                giorno_successivo INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                stato_generale TEXT NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                confermata_at TEXT
            );
            CREATE TABLE disponibilita_settimanale_categoria (
                profilo_categoria_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                fascia TEXT NOT NULL
            );
            CREATE TABLE disponibilita_intervalli_categoria (
                profilo_categoria_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                ora_inizio TEXT NOT NULL,
                ora_fine TEXT NOT NULL,
                giorno_successivo INTEGER NOT NULL DEFAULT 0
            );
        """)

    def tearDown(self):
        self.conn.close()

    @staticmethod
    def _fresh(days=2):
        return (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).strftime("%Y-%m-%d %H:%M:%S")

    def _add_general(
        self,
        user_id,
        *,
        weekly=(),
        intervals=(),
        on_call=False,
        status="disponibile",
        age_days=2,
        listing_type="offro",
        category="babysitter",
    ):
        self.conn.execute(
            "INSERT INTO annunci (id, utente_id, tipo_annuncio, categoria) "
            "VALUES (?, ?, ?, ?)",
            (user_id, user_id, listing_type, category),
        )
        self.conn.execute(
            "INSERT INTO disponibilita_profili "
            "(utente_id, stato_generale, a_chiamata, confermata_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, status, int(on_call), self._fresh(age_days)),
        )
        self.conn.executemany(
            "INSERT INTO disponibilita_settimanale "
            "(utente_id, giorno_settimana, fascia) VALUES (?, ?, ?)",
            [(user_id, day, slot) for day, slot in weekly],
        )
        self.conn.executemany(
            "INSERT INTO disponibilita_intervalli "
            "(utente_id, giorno_settimana, ora_inizio, ora_fine, "
            "giorno_successivo) VALUES (?, ?, ?, ?, ?)",
            [
                (user_id, day, start, end, int(next_day))
                for day, start, end, next_day in intervals
            ],
        )
        self.conn.commit()

    def _add_category(
        self,
        user_id,
        *,
        profile_id=None,
        weekly=(),
        intervals=(),
        on_call=False,
        status="disponibile",
        age_days=2,
        category="babysitter",
    ):
        profile_id = profile_id or user_id * 100
        self.conn.execute(
            "INSERT INTO disponibilita_profili_categoria "
            "(id, utente_id, categoria_slug, stato_generale, a_chiamata, "
            "confermata_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                profile_id,
                user_id,
                category,
                status,
                int(on_call),
                self._fresh(age_days),
            ),
        )
        self.conn.executemany(
            "INSERT INTO disponibilita_settimanale_categoria "
            "(profilo_categoria_id, giorno_settimana, fascia) "
            "VALUES (?, ?, ?)",
            [(profile_id, day, slot) for day, slot in weekly],
        )
        self.conn.executemany(
            "INSERT INTO disponibilita_intervalli_categoria "
            "(profilo_categoria_id, giorno_settimana, ora_inizio, ora_fine, "
            "giorno_successivo) VALUES (?, ?, ?, ?, ?)",
            [
                (profile_id, day, start, end, int(next_day))
                for day, start, end, next_day in intervals
            ],
        )
        self.conn.commit()

    def _criteria(self, values=None):
        return self.backend["_normalizza_filtri_disponibilita_cerca"](
            MultiArgs(values)
        )

    def _matches(self, criteria):
        expression = self.backend["_disponibilita_filtro_cerca_sql"](
            self.conn.cursor(),
            criteria,
        )
        return [
            int(row["id"])
            for row in self.conn.execute(
                f"SELECT a.id FROM annunci a WHERE ({expression}) "
                "ORDER BY a.id"
            ).fetchall()
        ]

    def test_parser_preserva_parametri_ripetuti_e_non_inventa_fasce(self):
        criteria = self._criteria({
            "disponibilita_giorni": ["2", "1", "2"],
            "disponibilita_fasce": ["sera", "mattina", "sera"],
            "disponibilita_dalle": "10:00",
            "disponibilita_alle": "14:00",
            "disponibilita_a_chiamata": "1",
        })

        self.assertEqual(criteria["giorni"], (1, 2))
        self.assertEqual(criteria["fasce"], ("sera", "mattina"))
        self.assertEqual(criteria["dalle"], "10:00")
        self.assertEqual(criteria["alle"], "14:00")
        self.assertFalse(criteria["giorno_successivo"])
        self.assertTrue(criteria["a_chiamata"])
        self.assertTrue(criteria["dettaglio_richiesto"])
        self.assertFalse(self._criteria()["dettaglio_richiesto"])

    def test_parser_valida_intervallo_e_supporta_notte_inferita(self):
        night = self._criteria({
            "disponibilita_giorni": "1",
            "disponibilita_dalle": "22:00",
            "disponibilita_alle": "02:00",
        })
        self.assertTrue(night["giorno_successivo"])

        invalid = (
            {"disponibilita_dalle": "10:00", "disponibilita_alle": "12:00"},
            {"disponibilita_giorni": "1", "disponibilita_dalle": "10:00"},
            {
                "disponibilita_giorni": "1",
                "disponibilita_dalle": "10:00",
                "disponibilita_alle": "10:00",
            },
            {
                "disponibilita_giorni": "1",
                "disponibilita_dalle": "17:00",
                "disponibilita_alle": "02:00",
            },
            {"disponibilita_giorni": "8"},
            {"disponibilita_fasce": "pranzo"},
            {"disponibilita_a_chiamata": "si"},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                self._criteria(values)

    def test_tutti_i_giorni_devono_contenere_tutte_le_fasce(self):
        complete = [(1, "mattina"), (1, "sera"), (2, "mattina"), (2, "sera")]
        self._add_general(1, weekly=complete)
        self._add_general(2, weekly=complete[:-1])
        criteria = self._criteria({
            "disponibilita_giorni": ["1", "2"],
            "disponibilita_fasce": ["mattina", "sera"],
        })

        self.assertEqual(self._matches(criteria), [1])

    def test_fasce_senza_giorni_devono_coesistere_nello_stesso_giorno(self):
        self._add_general(1, weekly=[(1, "mattina"), (2, "sera")])
        self._add_general(2, weekly=[(3, "mattina"), (3, "sera")])
        criteria = self._criteria({
            "disponibilita_fasce": ["mattina", "sera"],
        })

        self.assertEqual(self._matches(criteria), [2])

    def test_giorno_solo_accetta_fascia_intervallo_o_coda_notturna_precedente(self):
        self._add_general(1, weekly=[(1, "mattina")])
        self._add_general(2, intervals=[(1, "10:00", "12:00", False)])
        self._add_general(3, intervals=[(7, "22:00", "03:00", True)])
        self._add_general(4, intervals=[(7, "22:00", "00:00", True)])
        criteria = self._criteria({"disponibilita_giorni": "1"})

        self.assertEqual(self._matches(criteria), [1, 2, 3])

    def test_intervallo_preciso_richiede_contenimento_in_una_sola_riga_reale(self):
        self._add_general(1, intervals=[(1, "09:00", "17:00", False)])
        self._add_general(2, intervals=[(1, "10:00", "13:00", False)])
        self._add_general(3, weekly=[(1, "mattina"), (1, "pomeriggio")])
        self._add_general(4, intervals=[
            (1, "09:00", "14:00", False),
            (1, "14:00", "18:00", False),
        ])
        criteria = self._criteria({
            "disponibilita_giorni": "1",
            "disponibilita_dalle": "10:00",
            "disponibilita_alle": "17:00",
        })

        self.assertEqual(self._matches(criteria), [1])

    def test_intervallo_notturno_stesso_giorno_e_contenuto(self):
        self._add_general(1, intervals=[(1, "21:00", "03:00", True)])
        self._add_general(2, intervals=[(1, "22:00", "01:00", True)])
        self._add_general(3, intervals=[(7, "21:00", "03:00", True)])
        criteria = self._criteria({
            "disponibilita_giorni": "1",
            "disponibilita_dalle": "22:00",
            "disponibilita_alle": "02:00",
        })

        self.assertEqual(self._matches(criteria), [1])

    def test_intervallo_preciso_deve_essere_coperto_in_ogni_giorno_scelto(self):
        self._add_general(1, intervals=[
            (1, "09:00", "17:00", False),
            (2, "09:00", "17:00", False),
        ])
        self._add_general(2, intervals=[(1, "09:00", "17:00", False)])
        criteria = self._criteria({
            "disponibilita_giorni": ["1", "2"],
            "disponibilita_dalle": "10:00",
            "disponibilita_alle": "14:00",
        })

        self.assertEqual(self._matches(criteria), [1])

    def test_mattina_presto_combacia_con_notte_del_giorno_precedente(self):
        # Lunedì 01:00-02:00 e coperto dalla domenica 22:00-03:00.
        self._add_general(1, intervals=[(7, "22:00", "03:00", True)])
        self._add_general(2, intervals=[(1, "00:00", "03:00", False)])
        self._add_general(3, intervals=[(7, "22:00", "01:00", True)])
        criteria = self._criteria({
            "disponibilita_giorni": "1",
            "disponibilita_dalle": "01:00",
            "disponibilita_alle": "02:00",
        })

        self.assertEqual(self._matches(criteria), [1, 2])

    def test_mattina_presto_funziona_anche_senza_wrap_settimanale(self):
        # Martedì 01:00-02:00 e coperto dalla notte iniziata lunedì.
        self._add_general(1, intervals=[(1, "22:00", "03:00", True)])
        criteria = self._criteria({
            "disponibilita_giorni": "2",
            "disponibilita_dalle": "01:00",
            "disponibilita_alle": "02:00",
        })

        self.assertEqual(self._matches(criteria), [1])

    def test_a_chiamata_e_un_criterio_aggiuntivo_and(self):
        self._add_general(1, weekly=[(1, "mattina")], on_call=True)
        self._add_general(2, weekly=[(2, "mattina")], on_call=True)
        self._add_general(3, weekly=[(1, "mattina")], on_call=False)
        criteria = self._criteria({
            "disponibilita_giorni": "1",
            "disponibilita_fasce": "mattina",
            "disponibilita_a_chiamata": "1",
        })

        self.assertEqual(self._matches(criteria), [1])

    def test_override_categoria_non_mescola_calendario_generale(self):
        self._add_general(1, weekly=[(1, "mattina"), (1, "sera")])
        self._add_category(1, weekly=[(1, "mattina")])
        self._add_general(2, weekly=[(1, "mattina"), (1, "sera")])
        self._add_general(3, intervals=[(1, "09:00", "17:00", False)])
        self._add_category(3, intervals=[(1, "10:00", "13:00", False)])
        self._add_general(4)
        self._add_category(4, intervals=[(1, "09:00", "17:00", False)])

        slots = self._criteria({
            "disponibilita_giorni": "1",
            "disponibilita_fasce": ["mattina", "sera"],
        })
        exact = self._criteria({
            "disponibilita_giorni": "1",
            "disponibilita_dalle": "10:00",
            "disponibilita_alle": "14:00",
        })

        self.assertEqual(self._matches(slots), [2])
        self.assertEqual(self._matches(exact), [4])

    def test_esclude_cerco_stato_non_disponibile_e_conferma_vecchia(self):
        self._add_general(1, weekly=[(1, "mattina")], listing_type="offro")
        self._add_general(2, weekly=[(1, "mattina")], listing_type="cerco")
        self._add_general(
            3,
            weekly=[(1, "mattina")],
            status="non_disponibile",
        )
        self._add_general(
            4,
            weekly=[(1, "mattina")],
            age_days=GIORNI_ESCLUSIONE_FILTRO + 1,
        )
        criteria = self._criteria({"disponibilita_giorni": "1"})

        self.assertEqual(self._matches(criteria), [1])


if __name__ == "__main__":
    unittest.main()
