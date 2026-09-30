import ast
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from ciclo_disponibilita_annunci import (
    EVENTO_ARCHIVIATO,
    EVENTO_ROLLOUT_INVITO,
    EVENTO_ROLLOUT_PROMEMORIA_1,
    EVENTO_ROLLOUT_PROMEMORIA_2,
    EVENTO_ROLLOUT_ULTIMO_AVVISO,
    ORIGINE_ORDINARIA,
    ORIGINE_ROLLOUT,
    STATO_ARCHIVIATO,
    STATO_ATTIVO,
    STATO_NON_DISPONIBILE,
    pianifica_ciclo_annuncio,
    utc_datetime,
)
from disponibilita_servizi import (
    CATEGORIE_SERVIZI,
    GIORNI_ESCLUSIONE_FILTRO,
    GIORNI_PROMEMORIA_SCADENZA,
    GIORNI_PRIORITA_RIDOTTA,
    GIORNI_RICONFERMA,
    calcola_freschezza_disponibilita,
)


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
UTC = timezone.utc
START = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


def _app_functions(*names):
    """Carica funzioni isolate di app.py senza avviare Flask o i worker."""

    wanted = set(names)
    tree = ast.parse(APP_SOURCE)
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    missing = wanted - {node.name for node in selected}
    if missing:
        raise AssertionError(f"Funzioni app.py mancanti: {sorted(missing)}")

    namespace = {
        "app": SimpleNamespace(config={"IS_POSTGRES": False}),
        "date": date,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "CATEGORIE_SERVIZI": CATEGORIE_SERVIZI,
        "GIORNI_PROMEMORIA_SCADENZA": GIORNI_PROMEMORIA_SCADENZA,
        "GIORNI_RICONFERMA": GIORNI_RICONFERMA,
        "GIORNI_PRIORITA_RIDOTTA": GIORNI_PRIORITA_RIDOTTA,
        "GIORNI_ESCLUSIONE_FILTRO": GIORNI_ESCLUSIONE_FILTRO,
        "DISPONIBILITA_PROMEMORIA_COOLDOWN_GIORNI": 3,
        "sql": lambda query: query,
    }
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    return namespace


def _profile(*, confirmed=START, reminded=None, category=None, row_id=None):
    result = {
        "confermata_at": confirmed,
        "ultimo_promemoria_at": reminded,
    }
    if category is not None:
        result["categoria_slug"] = category
    if row_id is not None:
        result["id"] = row_id
    return result


class CicloOrdinarioTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = _app_functions(
            "_disponibilita_promemoria_datetime",
            "_piano_promemoria_disponibilita",
        )

    def _reminder_plan(self, day, *, reminded=None):
        return self.backend["_piano_promemoria_disponibilita"](
            _profile(reminded=reminded),
            [],
            ["babysitter"],
            adesso=START + timedelta(days=day),
        )

    def test_ciclo_ordinario_rispetta_esattamente_25_30_37_44(self):
        self.assertIsNone(self._reminder_plan(24))

        day_25 = self._reminder_plan(25)
        self.assertEqual(day_25["fase"], "in_scadenza")

        day_30 = self._reminder_plan(
            30,
            reminded=START + timedelta(days=25),
        )
        self.assertEqual(day_30["fase"], "scaduta")

        day_37 = self._reminder_plan(
            37,
            reminded=START + timedelta(days=30),
        )
        self.assertEqual(day_37["fase"], "ultimo_avviso")

        before_unavailable = pianifica_ciclo_annuncio(
            origine=ORIGINE_ORDINARIA,
            iniziato_at=START,
            confermata_at=START,
            now=START + timedelta(days=36, hours=23, minutes=59),
        )
        self.assertEqual(before_unavailable["stato"], STATO_ATTIVO)
        self.assertFalse(before_unavailable["non_disponibile_effettiva"])

        unavailable = pianifica_ciclo_annuncio(
            origine=ORIGINE_ORDINARIA,
            iniziato_at=START,
            confermata_at=START,
            now=START + timedelta(days=37),
        )
        self.assertEqual(unavailable["stato"], STATO_NON_DISPONIBILE)
        self.assertTrue(unavailable["non_disponibile_effettiva"])
        self.assertFalse(unavailable["archivia_ora"])

        before_archive = pianifica_ciclo_annuncio(
            origine=ORIGINE_ORDINARIA,
            iniziato_at=START,
            confermata_at=START,
            now=START + timedelta(days=43, hours=23, minutes=59),
        )
        self.assertFalse(before_archive["archivia_ora"])

        archived = pianifica_ciclo_annuncio(
            origine=ORIGINE_ORDINARIA,
            iniziato_at=START,
            confermata_at=START,
            now=START + timedelta(days=44),
        )
        self.assertEqual(archived["stato"], STATO_ARCHIVIATO)
        self.assertTrue(archived["archivia_ora"])
        self.assertIn(EVENTO_ARCHIVIATO, archived["eventi_dovuti"])

    def test_non_disponibile_volontario_esce_subito_senza_eventi(self):
        plan = pianifica_ciclo_annuncio(
            origine=ORIGINE_ORDINARIA,
            iniziato_at=START,
            confermata_at=START,
            stato_disponibilita="non_disponibile",
            now=START + timedelta(days=1),
        )

        self.assertEqual(plan["stato"], STATO_ARCHIVIATO)
        self.assertTrue(plan["archivia_ora"])
        self.assertIsNone(plan["archive_due_at"])
        self.assertEqual(plan["eventi_dovuti"], [])

    def test_non_disponibile_volontario_non_riceve_reminder(self):
        plan = self.backend["_piano_promemoria_disponibilita"](
            {
                **_profile(confirmed=START - timedelta(days=60)),
                "stato_generale": "non_disponibile",
            },
            [],
            ["babysitter"],
            adesso=START,
        )

        self.assertIsNone(plan)


class RolloutTest(unittest.TestCase):
    def _plan(self, day, sent=()):
        return pianifica_ciclo_annuncio(
            origine=ORIGINE_ROLLOUT,
            iniziato_at=START,
            now=START + timedelta(days=day),
            eventi_inviati=sent,
        )

    def test_rollout_rispetta_0_7_14_21_28_ed_e_idempotente(self):
        sent = []
        expected = (
            (0, EVENTO_ROLLOUT_INVITO),
            (7, EVENTO_ROLLOUT_PROMEMORIA_1),
            (14, EVENTO_ROLLOUT_PROMEMORIA_2),
            (21, EVENTO_ROLLOUT_ULTIMO_AVVISO),
        )
        for day, event in expected:
            with self.subTest(day=day):
                plan = self._plan(day, sent)
                self.assertEqual(plan["eventi_dovuti"], [event])
                sent.append(event)

        day_21 = self._plan(21, sent)
        self.assertEqual(day_21["stato"], STATO_NON_DISPONIBILE)
        self.assertTrue(day_21["non_disponibile_effettiva"])
        self.assertFalse(day_21["archivia_ora"])

        day_28 = self._plan(28, sent)
        self.assertEqual(day_28["stato"], STATO_ARCHIVIATO)
        self.assertTrue(day_28["archivia_ora"])
        self.assertEqual(day_28["eventi_dovuti"], [EVENTO_ARCHIVIATO])

        already_archived = self._plan(28, [*sent, EVENTO_ARCHIVIATO])
        self.assertEqual(already_archived["eventi_dovuti"], [])

    def test_job_arretrato_invia_solo_la_fase_rollout_piu_urgente(self):
        plan = self._plan(15)
        self.assertEqual(
            plan["eventi_dovuti"],
            [EVENTO_ROLLOUT_PROMEMORIA_2],
        )


class ApprovazioneAnnuncioDisponibilitaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = _app_functions(
            "_profilo_disponibilita_effettivo_annuncio",
            "_annuncio_bloccato_dalla_disponibilita",
            "_approva_annuncio_con_disponibilita",
            "_reset_ciclo_disponibilita_annunci",
        )
        cls.backend.update({
            "to_slug": lambda value: str(value or "").strip().lower(),
            "calcola_freschezza_disponibilita": (
                calcola_freschezza_disponibilita
            ),
            "now_sql": lambda: "CURRENT_TIMESTAMP",
            "_disponibilita_servizi_table_exists": lambda cur: True,
            "_disponibilita_categoria_table_exists": lambda cur: True,
            "_annunci_disponibilita_ciclo_tables_exist": lambda cur: True,
            "_annulla_promemoria_disponibilita_pendenti": (
                lambda cur, user_id, categoria_slug=None: 0
            ),
        })

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria TEXT NOT NULL,
                tipo_annuncio TEXT NOT NULL,
                stato TEXT NOT NULL,
                approvato_il TEXT,
                match_da_processare INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                stato_generale TEXT NOT NULL,
                confermata_at TEXT
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                stato_generale TEXT NOT NULL,
                confermata_at TEXT,
                UNIQUE (utente_id, categoria_slug)
            );
            CREATE TABLE annunci_disponibilita_ciclo (
                annuncio_id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                origine TEXT NOT NULL,
                stato TEXT NOT NULL,
                ciclo_versione INTEGER NOT NULL DEFAULT 1,
                ciclo_iniziato_at TEXT NOT NULL,
                confermata_at_snapshot TEXT,
                non_disponibile_at TEXT,
                archiviazione_prevista_at TEXT,
                archiviato_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)

    def tearDown(self):
        self.conn.close()

    def test_offro_non_disponibile_e_approvato_ma_resta_archiviato(self):
        for scope in ("categoria", "generale"):
            with self.subTest(scope=scope):
                self.conn.execute("DELETE FROM annunci_disponibilita_ciclo")
                self.conn.execute("DELETE FROM disponibilita_profili_categoria")
                self.conn.execute("DELETE FROM disponibilita_profili")
                self.conn.execute("DELETE FROM annunci")
                self.conn.execute("""
                    INSERT INTO annunci (
                        id, utente_id, categoria, tipo_annuncio, stato
                    ) VALUES (1, 7, 'babysitter', 'offro', 'in_attesa')
                """)
                if scope == "categoria":
                    self.conn.execute("""
                        INSERT INTO disponibilita_profili_categoria (
                            utente_id, categoria_slug, stato_generale,
                            confermata_at
                        ) VALUES (7, 'babysitter', 'non_disponibile', ?)
                    """, (START.isoformat(),))
                else:
                    self.conn.execute("""
                        INSERT INTO disponibilita_profili (
                            utente_id, stato_generale, confermata_at
                        ) VALUES (7, 'non_disponibile', ?)
                    """, (START.isoformat(),))

                result = self.backend[
                    "_approva_annuncio_con_disponibilita"
                ](self.conn.cursor(), 1)

                listing = self.conn.execute("""
                    SELECT stato, approvato_il, match_da_processare
                    FROM annunci WHERE id = 1
                """).fetchone()
                self.assertEqual(
                    listing["stato"],
                    "archiviato_disponibilita",
                )
                self.assertIsNotNone(listing["approvato_il"])
                self.assertEqual(listing["match_da_processare"], 0)
                self.assertTrue(result["archiviato_per_disponibilita"])
                cycle = self.conn.execute("""
                    SELECT stato, archiviato_at
                    FROM annunci_disponibilita_ciclo
                    WHERE annuncio_id = 1
                """).fetchone()
                self.assertEqual(cycle["stato"], "archiviato")
                self.assertIsNotNone(cycle["archiviato_at"])

    def test_offro_disponibile_diventa_pubblico(self):
        self.conn.execute("""
            INSERT INTO annunci (
                id, utente_id, categoria, tipo_annuncio, stato
            ) VALUES (2, 7, 'babysitter', 'offro', 'in_attesa')
        """)
        self.conn.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale, confermata_at
            ) VALUES (7, 'babysitter', 'disponibile', ?)
        """, (datetime.now(timezone.utc).isoformat(),))

        result = self.backend["_approva_annuncio_con_disponibilita"](
            self.conn.cursor(), 2
        )

        listing = self.conn.execute("""
            SELECT stato, approvato_il, match_da_processare
            FROM annunci WHERE id = 2
        """).fetchone()
        self.assertEqual(tuple(listing), ("approvato", listing[1], 1))
        self.assertIsNotNone(listing["approvato_il"])
        self.assertFalse(result["archiviato_per_disponibilita"])

    def test_entrambi_i_percorsi_admin_usano_lo_stesso_helper(self):
        toggle_start = APP_SOURCE.index("def toggle_annuncio(id):")
        toggle_end = APP_SOURCE.index("# ==========================", toggle_start)
        approve_start = APP_SOURCE.index("def approva_annuncio(id):")
        approve_end = APP_SOURCE.index(
            '@app.route("/admin/annunci/rifiuta',
            approve_start,
        )

        self.assertIn(
            "_approva_annuncio_con_disponibilita(c, id)",
            APP_SOURCE[toggle_start:toggle_end],
        )
        self.assertIn(
            "_approva_annuncio_con_disponibilita(c, id)",
            APP_SOURCE[approve_start:approve_end],
        )


class ResetAcquistoEArchivioTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = _app_functions(
            "_annulla_promemoria_disponibilita_pendenti",
            "_reset_ciclo_disponibilita_annunci",
            "_riconferma_disponibilita_acquisto",
            "_categorie_annunci_disponibilita_rilevanti",
            "_riconferma_o_crea_disponibilita_categoria",
            "_riconferma_tutte_disponibilita_annunci",
        )
        cls.backend.update({
            "_annunci_disponibilita_ciclo_tables_exist": lambda cur: True,
            "_disponibilita_promemoria_outbox_table_exists": lambda cur: True,
            "_disponibilita_categoria_table_exists": lambda cur: True,
            "_disponibilita_intervalli_table_exists": (
                lambda cur, categoria=False: True
            ),
            "to_slug": lambda value: str(value or "").strip().lower(),
        })

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria TEXT NOT NULL,
                tipo_annuncio TEXT NOT NULL,
                stato TEXT NOT NULL
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                stato_generale TEXT NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                fuso_orario TEXT NOT NULL DEFAULT 'Europe/Rome',
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (utente_id, categoria_slug)
            );
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                stato_generale TEXT NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                fuso_orario TEXT NOT NULL DEFAULT 'Europe/Rome',
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE annunci_disponibilita_ciclo (
                annuncio_id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                origine TEXT NOT NULL,
                stato TEXT NOT NULL,
                ciclo_versione INTEGER NOT NULL DEFAULT 1,
                ciclo_iniziato_at TEXT NOT NULL,
                confermata_at_snapshot TEXT,
                non_disponibile_at TEXT,
                archiviazione_prevista_at TEXT,
                archiviato_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE disponibilita_promemoria_eventi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                link TEXT NOT NULL,
                notifica_interna_at TEXT,
                push_inviata_at TEXT,
                email_inviata_at TEXT
            );
            CREATE TABLE disponibilita_settimanale_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                fascia TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (profilo_categoria_id, giorno_settimana, fascia)
            );
            CREATE TABLE disponibilita_intervalli_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                ora_inizio TEXT NOT NULL,
                ora_fine TEXT NOT NULL,
                giorno_successivo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (
                    profilo_categoria_id, giorno_settimana,
                    ora_inizio, ora_fine, giorno_successivo
                )
            );
            CREATE TABLE disponibilita_settimanale (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                fascia TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (utente_id, giorno_settimana, fascia)
            );
            CREATE TABLE disponibilita_intervalli (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                ora_inizio TEXT NOT NULL,
                ora_fine TEXT NOT NULL,
                giorno_successivo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (
                    utente_id, giorno_settimana,
                    ora_inizio, ora_fine, giorno_successivo
                )
            );
            CREATE TABLE disponibilita_date_speciali (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                data TEXT NOT NULL,
                tipo TEXT NOT NULL,
                fasce TEXT NOT NULL DEFAULT '[]',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE disponibilita_date_speciali_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER NOT NULL,
                data TEXT NOT NULL,
                tipo TEXT NOT NULL,
                fasce TEXT NOT NULL DEFAULT '[]',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (profilo_categoria_id, data)
            );
            CREATE TABLE disponibilita_assenze (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                data_inizio TEXT NOT NULL,
                data_fine TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE disponibilita_assenze_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profilo_categoria_id INTEGER NOT NULL,
                data_inizio TEXT NOT NULL,
                data_fine TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (profilo_categoria_id, data_inizio, data_fine)
            );
        """)

    def tearDown(self):
        self.conn.close()

    def test_acquisto_reimposta_disponibilita_e_nuovo_ciclo(self):
        self.conn.execute(
            "INSERT INTO annunci VALUES (1, 7, 'babysitter', 'offro', 'approvato')"
        )
        self.conn.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale, a_chiamata,
                confermata_at, ultimo_promemoria_at, versione
            ) VALUES (7, 'babysitter', 'non_disponibile', 1, ?, ?, 4)
        """, (
            (START - timedelta(days=60)).isoformat(),
            (START - timedelta(days=23)).isoformat(),
        ))
        profile_id = self.conn.execute("""
            SELECT id FROM disponibilita_profili_categoria
            WHERE utente_id = 7 AND categoria_slug = 'babysitter'
        """).fetchone()["id"]
        self.conn.execute("""
            INSERT INTO disponibilita_settimanale_categoria (
                profilo_categoria_id, giorno_settimana, fascia
            ) VALUES (?, 2, 'mattina')
        """, (profile_id,))
        self.conn.execute("""
            INSERT INTO disponibilita_intervalli_categoria (
                profilo_categoria_id, giorno_settimana,
                ora_inizio, ora_fine, giorno_successivo
            ) VALUES (?, 2, '09:00', '12:30', 0)
        """, (profile_id,))
        self.conn.execute("""
            INSERT INTO annunci_disponibilita_ciclo (
                annuncio_id, utente_id, origine, stato, ciclo_versione,
                ciclo_iniziato_at, confermata_at_snapshot,
                non_disponibile_at, archiviazione_prevista_at, archiviato_at
            ) VALUES (1, 7, 'ordinario', 'non_disponibile_scadenza', 3,
                      ?, ?, ?, ?, NULL)
        """, (
            (START - timedelta(days=60)).isoformat(),
            (START - timedelta(days=60)).isoformat(),
            (START - timedelta(days=23)).isoformat(),
            (START - timedelta(days=16)).isoformat(),
        ))

        changed = self.backend["_riconferma_disponibilita_acquisto"](
            self.conn.cursor(), 7, 1
        )
        self.assertTrue(changed)

        availability = self.conn.execute("""
            SELECT stato_generale, a_chiamata, confermata_at,
                   ultimo_promemoria_at, versione
            FROM disponibilita_profili_categoria
            WHERE utente_id = 7 AND categoria_slug = 'babysitter'
        """).fetchone()
        self.assertEqual(availability["stato_generale"], "disponibile")
        # Il pagamento non cancella le preferenze facoltative gia scelte.
        self.assertEqual(availability["a_chiamata"], 1)
        self.assertIsNotNone(availability["confermata_at"])
        self.assertIsNone(availability["ultimo_promemoria_at"])
        self.assertEqual(availability["versione"], 5)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) AS n FROM disponibilita_settimanale_categoria"
            ).fetchone()["n"],
            1,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) AS n FROM disponibilita_intervalli_categoria"
            ).fetchone()["n"],
            1,
        )

        cycle = self.conn.execute("""
            SELECT origine, stato, ciclo_versione, non_disponibile_at,
                   archiviazione_prevista_at, archiviato_at
            FROM annunci_disponibilita_ciclo WHERE annuncio_id = 1
        """).fetchone()
        self.assertEqual(cycle["origine"], "ordinario")
        self.assertEqual(cycle["stato"], "attivo")
        self.assertEqual(cycle["ciclo_versione"], 4)
        self.assertIsNone(cycle["non_disponibile_at"])
        self.assertIsNone(cycle["archiviazione_prevista_at"])
        self.assertIsNone(cycle["archiviato_at"])

    def test_acquisto_crea_categoria_copiando_tutto_il_fallback_generale(self):
        self.conn.execute(
            "INSERT INTO annunci VALUES "
            "(3, 7, 'pet-sitter', 'offro', 'approvato')"
        )
        self.conn.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, a_chiamata, fuso_orario,
                confermata_at, versione
            ) VALUES (7, 'non_disponibile', 1, 'Europe/Rome', ?, 3)
        """, ((START - timedelta(days=60)).isoformat(),))
        self.conn.execute("""
            INSERT INTO disponibilita_settimanale (
                utente_id, giorno_settimana, fascia
            ) VALUES (7, 4, 'sera')
        """)
        self.conn.execute("""
            INSERT INTO disponibilita_intervalli (
                utente_id, giorno_settimana, ora_inizio, ora_fine,
                giorno_successivo
            ) VALUES (7, 5, '22:00', '02:00', 1)
        """)
        self.conn.execute("""
            INSERT INTO disponibilita_date_speciali (
                utente_id, data, tipo, fasce
            ) VALUES (7, '2026-10-15', 'disponibile', '["mattina"]')
        """)
        self.conn.execute("""
            INSERT INTO disponibilita_assenze (
                utente_id, data_inizio, data_fine
            ) VALUES (7, '2026-11-01', '2026-11-03')
        """)

        changed = self.backend["_riconferma_disponibilita_acquisto"](
            self.conn.cursor(), 7, 3
        )

        self.assertTrue(changed)
        profile = self.conn.execute("""
            SELECT id, stato_generale, a_chiamata, fuso_orario,
                   confermata_at
            FROM disponibilita_profili_categoria
            WHERE utente_id = 7 AND categoria_slug = 'pet-sitter'
        """).fetchone()
        self.assertEqual(profile["stato_generale"], "disponibile")
        self.assertEqual(profile["a_chiamata"], 1)
        self.assertEqual(profile["fuso_orario"], "Europe/Rome")
        self.assertIsNotNone(profile["confermata_at"])
        self.assertEqual(
            tuple(self.conn.execute("""
                SELECT giorno_settimana, fascia
                FROM disponibilita_settimanale_categoria
                WHERE profilo_categoria_id = ?
            """, (profile["id"],)).fetchone()),
            (4, "sera"),
        )
        self.assertEqual(
            tuple(self.conn.execute("""
                SELECT giorno_settimana, ora_inizio, ora_fine,
                       giorno_successivo
                FROM disponibilita_intervalli_categoria
                WHERE profilo_categoria_id = ?
            """, (profile["id"],)).fetchone()),
            (5, "22:00", "02:00", 1),
        )
        special = self.conn.execute("""
            SELECT data, tipo, fasce
            FROM disponibilita_date_speciali_categoria
            WHERE profilo_categoria_id = ?
        """, (profile["id"],)).fetchone()
        self.assertEqual(
            tuple(special),
            ("2026-10-15", "disponibile", '["mattina"]'),
        )
        absence = self.conn.execute("""
            SELECT data_inizio, data_fine
            FROM disponibilita_assenze_categoria
            WHERE profilo_categoria_id = ?
        """, (profile["id"],)).fetchone()
        self.assertEqual(tuple(absence), ("2026-11-01", "2026-11-03"))

    def test_conferma_riattiva_archivio_senza_cancellare_annuncio(self):
        self.conn.execute(
            "INSERT INTO annunci VALUES "
            "(9, 7, 'babysitter', 'offro', 'archiviato_disponibilita')"
        )
        self.conn.execute("""
            INSERT INTO annunci_disponibilita_ciclo (
                annuncio_id, utente_id, origine, stato, ciclo_versione,
                ciclo_iniziato_at, confermata_at_snapshot,
                non_disponibile_at, archiviazione_prevista_at, archiviato_at
            ) VALUES (9, 7, 'ordinario', 'archiviato', 2, ?, ?, ?, ?, ?)
        """, (START.isoformat(),) * 5)

        count = self.backend["_reset_ciclo_disponibilita_annunci"](
            self.conn.cursor(),
            7,
            categoria_slug="babysitter",
            stato_disponibilita="disponibile",
        )
        self.assertEqual(count, 1)
        self.assertEqual(
            self.conn.execute(
                "SELECT stato FROM annunci WHERE id = 9"
            ).fetchone()["stato"],
            "approvato",
        )
        cycle = self.conn.execute("""
            SELECT stato, ciclo_versione, archiviato_at
            FROM annunci_disponibilita_ciclo WHERE annuncio_id = 9
        """).fetchone()
        self.assertEqual(cycle["stato"], "attivo")
        self.assertEqual(cycle["ciclo_versione"], 3)
        self.assertIsNone(cycle["archiviato_at"])

    def test_non_disponibile_archivia_subito_categoria_e_annulla_outbox(self):
        self.conn.execute(
            "INSERT INTO annunci VALUES "
            "(31, 7, 'babysitter', 'offro', 'approvato')"
        )
        self.conn.execute("""
            INSERT INTO disponibilita_promemoria_eventi (
                utente_id, link
            ) VALUES (
                7,
                '/utente/dashboard?disponibilita=riconferma&categoria=babysitter'
            )
        """)

        count = self.backend["_reset_ciclo_disponibilita_annunci"](
            self.conn.cursor(),
            7,
            categoria_slug="babysitter",
            stato_disponibilita="non_disponibile",
        )

        self.assertEqual(count, 1)
        listing = self.conn.execute(
            "SELECT stato FROM annunci WHERE id = 31"
        ).fetchone()
        self.assertEqual(listing["stato"], "archiviato_disponibilita")
        cycle = self.conn.execute("""
            SELECT stato, non_disponibile_at,
                   archiviazione_prevista_at, archiviato_at
            FROM annunci_disponibilita_ciclo WHERE annuncio_id = 31
        """).fetchone()
        self.assertEqual(cycle["stato"], "archiviato")
        self.assertIsNotNone(cycle["non_disponibile_at"])
        self.assertIsNone(cycle["archiviazione_prevista_at"])
        self.assertIsNotNone(cycle["archiviato_at"])
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) AS n FROM disponibilita_promemoria_eventi"
            ).fetchone()["n"],
            0,
        )

    def test_non_disponibile_generale_non_archivia_categorie_con_override(self):
        self.conn.executemany(
            "INSERT INTO annunci VALUES (?, 7, ?, 'offro', 'approvato')",
            (
                (41, "babysitter"),
                (42, "pet-sitter"),
            ),
        )
        self.conn.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale
            ) VALUES (7, 'pet-sitter', 'disponibile')
        """)

        count = self.backend["_reset_ciclo_disponibilita_annunci"](
            self.conn.cursor(),
            7,
            stato_disponibilita="non_disponibile",
        )

        self.assertEqual(count, 1)
        states = self.conn.execute(
            "SELECT id, stato FROM annunci WHERE id IN (41, 42) ORDER BY id"
        ).fetchall()
        self.assertEqual(
            [(row["id"], row["stato"]) for row in states],
            [(41, "archiviato_disponibilita"), (42, "approvato")],
        )

    def test_duplicato_blocca_annuncio_e_non_reset_ciclo_archiviato(self):
        for duplicate_state in ("approvato", "in_attesa"):
            with self.subTest(duplicate_state=duplicate_state):
                self.conn.execute("DELETE FROM annunci_disponibilita_ciclo")
                self.conn.execute("DELETE FROM annunci")
                self.conn.execute(
                    "INSERT INTO annunci VALUES "
                    "(9, 7, 'babysitter', 'offro', 'archiviato_disponibilita')"
                )
                self.conn.execute(
                    "INSERT INTO annunci VALUES (?, 7, 'babysitter', 'offro', ?)",
                    (10, duplicate_state),
                )
                self.conn.execute("""
                    INSERT INTO annunci_disponibilita_ciclo (
                        annuncio_id, utente_id, origine, stato,
                        ciclo_versione, ciclo_iniziato_at,
                        confermata_at_snapshot, archiviato_at
                    ) VALUES (9, 7, 'ordinario', 'archiviato', 4, ?, ?, ?)
                """, (START.isoformat(),) * 3)

                count = self.backend["_reset_ciclo_disponibilita_annunci"](
                    self.conn.cursor(),
                    7,
                    categoria_slug="babysitter",
                    stato_disponibilita="disponibile",
                    annuncio_id=9,
                )
                self.assertEqual(count, 0)
                listing = self.conn.execute(
                    "SELECT stato FROM annunci WHERE id = 9"
                ).fetchone()
                self.assertEqual(listing["stato"], "archiviato_disponibilita")
                cycle = self.conn.execute("""
                    SELECT stato, ciclo_versione, archiviato_at
                    FROM annunci_disponibilita_ciclo WHERE annuncio_id = 9
                """).fetchone()
                self.assertEqual(cycle["stato"], "archiviato")
                self.assertEqual(cycle["ciclo_versione"], 4)
                self.assertIsNotNone(cycle["archiviato_at"])

    def test_conferma_tutte_rende_disponibili_e_continua_sui_duplicati(self):
        self.conn.executemany(
            "INSERT INTO annunci VALUES (?, 7, ?, 'offro', ?)",
            (
                (20, "babysitter", "archiviato_disponibilita"),
                (21, "pet-sitter", "archiviato_disponibilita"),
                (30, "caregiver", "approvato"),
                (31, "caregiver", "archiviato_disponibilita"),
            ),
        )
        self.conn.execute("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, a_chiamata, fuso_orario,
                confermata_at, versione
            ) VALUES (7, 'limitata', 1, 'Europe/Rome', ?, 2)
        """, ((START - timedelta(days=50)).isoformat(),))
        self.conn.execute("""
            INSERT INTO disponibilita_settimanale (
                utente_id, giorno_settimana, fascia
            ) VALUES (7, 3, 'pomeriggio')
        """)
        self.conn.execute("""
            INSERT INTO disponibilita_intervalli (
                utente_id, giorno_settimana, ora_inizio, ora_fine,
                giorno_successivo
            ) VALUES (7, 3, '14:00', '17:00', 0)
        """)
        self.conn.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale, a_chiamata,
                confermata_at, ultimo_promemoria_at, versione
            ) VALUES (7, 'babysitter', 'non_disponibile', 1, ?, ?, 4)
        """, ((START - timedelta(days=50)).isoformat(),) * 2)
        self.conn.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale, a_chiamata,
                confermata_at, ultimo_promemoria_at, versione
            ) VALUES (7, 'caregiver', 'non_disponibile', 1, ?, ?, 2)
        """, ((START - timedelta(days=50)).isoformat(),) * 2)
        babysitter_id = self.conn.execute("""
            SELECT id FROM disponibilita_profili_categoria
            WHERE utente_id = 7 AND categoria_slug = 'babysitter'
        """).fetchone()["id"]
        self.conn.execute("""
            INSERT INTO disponibilita_settimanale_categoria (
                profilo_categoria_id, giorno_settimana, fascia
            ) VALUES (?, 2, 'mattina')
        """, (babysitter_id,))
        for listing_id in (20, 21, 31):
            self.conn.execute("""
                INSERT INTO annunci_disponibilita_ciclo (
                    annuncio_id, utente_id, origine, stato, ciclo_versione,
                    ciclo_iniziato_at, confermata_at_snapshot, archiviato_at
                ) VALUES (?, 7, 'rollout', 'archiviato', 2, ?, ?, ?)
            """, (listing_id, START.isoformat(), START.isoformat(), START.isoformat()))

        result = self.backend["_riconferma_tutte_disponibilita_annunci"](
            self.conn.cursor(), 7
        )

        self.assertEqual(result["confermate"], 3)
        self.assertEqual(result["create"], 1)
        self.assertEqual(result["annunci_riattivati"], 2)
        self.assertEqual(result["conflitti"], 1)
        self.assertEqual(result["conflitti_annunci"], [{
            "annuncio_id": 31,
            "categoria_slug": "caregiver",
        }])
        babysitter = self.conn.execute("""
            SELECT stato_generale, a_chiamata, versione
            FROM disponibilita_profili_categoria
            WHERE utente_id = 7 AND categoria_slug = 'babysitter'
        """).fetchone()
        self.assertEqual(tuple(babysitter), ("disponibile", 1, 5))
        self.assertEqual(
            self.conn.execute("""
                SELECT COUNT(*) AS n
                FROM disponibilita_settimanale_categoria
                WHERE profilo_categoria_id = ?
            """, (babysitter_id,)).fetchone()["n"],
            1,
        )
        pet = self.conn.execute("""
            SELECT id, stato_generale, a_chiamata
            FROM disponibilita_profili_categoria
            WHERE utente_id = 7 AND categoria_slug = 'pet-sitter'
        """).fetchone()
        self.assertEqual(pet["stato_generale"], "disponibile")
        self.assertEqual(pet["a_chiamata"], 1)
        self.assertEqual(
            self.conn.execute("""
                SELECT COUNT(*) AS n
                FROM disponibilita_settimanale_categoria
                WHERE profilo_categoria_id = ?
            """, (pet["id"],)).fetchone()["n"],
            1,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT stato FROM annunci WHERE id = 21"
            ).fetchone()["stato"],
            "approvato",
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT stato FROM annunci WHERE id = 20"
            ).fetchone()["stato"],
            "approvato",
        )
        caregiver = self.conn.execute("""
            SELECT stato_generale, a_chiamata
            FROM disponibilita_profili_categoria
            WHERE utente_id = 7 AND categoria_slug = 'caregiver'
        """).fetchone()
        self.assertEqual(tuple(caregiver), ("disponibile", 1))
        self.assertEqual(
            self.conn.execute(
                "SELECT stato FROM annunci WHERE id = 31"
            ).fetchone()["stato"],
            "archiviato_disponibilita",
        )


class ConsegnaEventiCicloDisponibilitaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = _app_functions(
            "_consegna_eventi_ciclo_disponibilita",
        )
        cls.backend.update({
            "_annunci_disponibilita_ciclo_tables_exist": lambda cur: True,
            "_copy_evento_ciclo_disponibilita": (
                lambda code: ("Titolo", "Messaggio")
            ),
            "normalize_language": lambda value: value or "it",
            "translate_source": lambda value, language: value,
            "emit_update_notifications": lambda user_id: None,
            "invia_push": lambda *args, **kwargs: False,
            "_invia_email": lambda **kwargs: False,
        })

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "delivery.sqlite3"
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                email TEXT,
                nome TEXT,
                username TEXT,
                lingua_interfaccia TEXT,
                eliminato INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE annunci_disponibilita_ciclo (
                annuncio_id INTEGER PRIMARY KEY,
                ciclo_versione INTEGER NOT NULL,
                stato TEXT NOT NULL
            );
            CREATE TABLE annunci_disponibilita_eventi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                annuncio_id INTEGER NOT NULL,
                utente_id INTEGER NOT NULL,
                ciclo_versione INTEGER NOT NULL,
                codice TEXT NOT NULL,
                notifica_interna_at TEXT,
                push_inviata_at TEXT,
                email_inviata_at TEXT,
                push_tentativi INTEGER NOT NULL DEFAULT 0,
                email_tentativi INTEGER NOT NULL DEFAULT 0,
                ultimo_errore TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE notifiche (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                id_utente INTEGER NOT NULL,
                titolo TEXT,
                messaggio TEXT,
                link TEXT,
                tipo TEXT,
                letta INTEGER
            );
        """)
        conn.execute(
            "INSERT INTO utenti (id, username, lingua_interfaccia) "
            "VALUES (7, 'utente', 'it')"
        )
        # Il ciclo e gia archiviato ma il suo evento finale corrente deve
        # comunque essere consegnato.
        conn.execute(
            "INSERT INTO annunci_disponibilita_ciclo "
            "(annuncio_id, ciclo_versione, stato) VALUES (31, 2, 'archiviato')"
        )
        conn.executemany("""
            INSERT INTO annunci_disponibilita_eventi (
                annuncio_id, utente_id, ciclo_versione, codice,
                push_inviata_at, email_inviata_at
            ) VALUES (31, 7, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (
            (1, EVENTO_ROLLOUT_PROMEMORIA_2),
            (2, EVENTO_ARCHIVIATO),
        ))
        conn.commit()
        conn.close()
        self.backend["get_db_connection"] = self._connect
        self.backend["get_cursor"] = lambda conn: conn.cursor()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def test_ignora_versione_vecchia_ma_consegna_archivio_corrente(self):
        result = self.backend["_consegna_eventi_ciclo_disponibilita"]()

        self.assertEqual(result["notifiche"], 1)
        conn = self._connect()
        try:
            rows = conn.execute("""
                SELECT ciclo_versione, notifica_interna_at
                FROM annunci_disponibilita_eventi
                ORDER BY ciclo_versione
            """).fetchall()
            self.assertIsNone(rows[0]["notifica_interna_at"])
            self.assertIsNotNone(rows[1]["notifica_interna_at"])
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM notifiche"
                ).fetchone()["n"],
                1,
            )
        finally:
            conn.close()


class ProcessoCicloDisponibilitaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = _app_functions(
            "_normalizza_limite_ciclo_disponibilita",
            "_disponibilita_ciclo_effective_sql",
            "_semina_cicli_disponibilita_annunci",
            "_sincronizza_ciclo_con_conferma",
            "_inserisci_evento_ciclo_disponibilita",
            "processa_ciclo_disponibilita_annunci",
        )
        cls.backend.update({
            "DISPONIBILITA_ROLLOUT_PROVINCE": ("milano", "roma", "torino"),
            "DISPONIBILITA_CICLO_BATCH_DEFAULT": 500,
            "DISPONIBILITA_CICLO_BATCH_MAX": 2000,
            "EVENTO_ROLLOUT_INVITO": EVENTO_ROLLOUT_INVITO,
            "EVENTO_ROLLOUT_PROMEMORIA_1": EVENTO_ROLLOUT_PROMEMORIA_1,
            "EVENTO_ROLLOUT_PROMEMORIA_2": EVENTO_ROLLOUT_PROMEMORIA_2,
            "EVENTO_ROLLOUT_ULTIMO_AVVISO": EVENTO_ROLLOUT_ULTIMO_AVVISO,
            "ORIGINE_ORDINARIA": ORIGINE_ORDINARIA,
            "ORIGINE_ROLLOUT": ORIGINE_ROLLOUT,
            "pianifica_ciclo_annuncio": pianifica_ciclo_annuncio,
            "ciclo_disponibilita_datetime": utc_datetime,
            "sql": lambda query: query,
            "now_sql": lambda: "datetime('now')",
            "_disponibilita_categoria_table_exists": lambda cur: True,
            "_annunci_disponibilita_ciclo_tables_exist": lambda cur: True,
            "_schede_profilo_begin": lambda cur: cur.execute("BEGIN IMMEDIATE"),
            "_schede_profilo_commit": lambda cur: cur.connection.commit(),
            "_schede_profilo_rollback": lambda cur: cur.connection.rollback(),
            "_consegna_eventi_ciclo_disponibilita": (
                lambda limite=500: {
                    "notifiche": 0,
                    "push": 0,
                    "email": 0,
                    "errori": [],
                }
            ),
            "log_exception_safe": lambda *args, **kwargs: None,
        })

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "cycle.sqlite3"
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria TEXT NOT NULL,
                provincia TEXT,
                tipo_annuncio TEXT NOT NULL,
                stato TEXT NOT NULL,
                titolo TEXT,
                modalita_servizio TEXT DEFAULT 'presenza'
            );
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                stato_generale TEXT NOT NULL,
                confermata_at TEXT
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                stato_generale TEXT NOT NULL,
                confermata_at TEXT,
                UNIQUE (utente_id, categoria_slug)
            );
            CREATE TABLE annunci_disponibilita_ciclo (
                annuncio_id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                origine TEXT NOT NULL,
                stato TEXT NOT NULL,
                ciclo_versione INTEGER NOT NULL DEFAULT 1,
                ciclo_iniziato_at TEXT NOT NULL,
                confermata_at_snapshot TEXT,
                non_disponibile_at TEXT,
                archiviazione_prevista_at TEXT,
                archiviato_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE annunci_disponibilita_eventi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                annuncio_id INTEGER NOT NULL,
                utente_id INTEGER NOT NULL,
                ciclo_versione INTEGER NOT NULL,
                codice TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (annuncio_id, ciclo_versione, codice)
            );
            CREATE TABLE acquisti (
                id INTEGER PRIMARY KEY,
                stato TEXT,
                importo_cent INTEGER,
                metodo TEXT
            );
            CREATE TABLE attivazioni_servizi (
                id INTEGER PRIMARY KEY,
                annuncio_id INTEGER,
                acquisto_id INTEGER,
                stato TEXT,
                data_inizio TEXT,
                data_fine TEXT
            );
        """)
        conn.commit()
        conn.close()
        self.backend["get_db_connection"] = self._connect
        self.backend["get_cursor"] = lambda conn: conn.cursor()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _run(self):
        return self.backend["processa_ciclo_disponibilita_annunci"](
            limite=100,
            dry_run=False,
        )

    def test_rollout_include_province_pilota_e_tutti_gli_online(self):
        conn = self._connect()
        conn.executemany(
            """
            INSERT INTO annunci (
                id, utente_id, categoria, provincia, tipo_annuncio,
                stato, titolo, modalita_servizio
            ) VALUES (?, ?, ?, ?, 'offro', 'approvato', ?, ?)
            """,
            (
                (1, 10, "babysitter", "Milano", "Milano", "presenza"),
                (2, 11, "babysitter", "Napoli", "Napoli", "presenza"),
                (5, 14, "ripetizioni", None, "Online", "online"),
            ),
        )
        conn.commit()
        conn.close()

        result = self._run()

        self.assertTrue(result["ok"])
        self.assertEqual(result["cicli_creati"], 2)
        conn = self._connect()
        try:
            cycles = conn.execute(
                "SELECT annuncio_id, origine FROM annunci_disponibilita_ciclo"
            ).fetchall()
            self.assertEqual(
                [(row["annuncio_id"], row["origine"]) for row in cycles],
                [(1, "rollout"), (5, "rollout")],
            )
            self.assertEqual(
                conn.execute(
                    "SELECT codice FROM annunci_disponibilita_eventi"
                ).fetchone()["codice"],
                EVENTO_ROLLOUT_INVITO,
            )
        finally:
            conn.close()

    def test_processo_archivia_senza_cancellare_e_conserva_la_riga(self):
        confirmed = datetime.now(UTC) - timedelta(days=45)
        conn = self._connect()
        conn.execute(
            """
            INSERT INTO annunci (
                id, utente_id, categoria, provincia, tipo_annuncio,
                stato, titolo, modalita_servizio
            ) VALUES (
                3, 12, 'babysitter', 'Milano', 'offro',
                'approvato', 'Test', 'presenza'
            )
            """
        )
        conn.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale, confermata_at
            ) VALUES (12, 'babysitter', 'disponibile', ?)
        """, (confirmed.isoformat(),))
        conn.commit()
        conn.close()

        result = self._run()

        self.assertTrue(result["ok"])
        self.assertEqual(result["annunci_archiviati"], 1)
        conn = self._connect()
        try:
            listing = conn.execute(
                "SELECT id, titolo, stato FROM annunci WHERE id = 3"
            ).fetchone()
            self.assertEqual(listing["titolo"], "Test")
            self.assertEqual(listing["stato"], "archiviato_disponibilita")
            cycle = conn.execute("""
                SELECT stato, archiviato_at
                FROM annunci_disponibilita_ciclo WHERE annuncio_id = 3
            """).fetchone()
            self.assertEqual(cycle["stato"], STATO_ARCHIVIATO)
            self.assertIsNotNone(cycle["archiviato_at"])
        finally:
            conn.close()

    def test_servizio_attivo_non_deroga_al_ciclo_ripartito_dall_acquisto(self):
        now = datetime.now(UTC)
        confirmed = now - timedelta(days=50)
        conn = self._connect()
        conn.execute(
            """
            INSERT INTO annunci (
                id, utente_id, categoria, provincia, tipo_annuncio,
                stato, titolo, modalita_servizio
            ) VALUES (
                4, 13, 'babysitter', 'Milano', 'offro',
                'approvato', 'Paid', 'presenza'
            )
            """
        )
        conn.execute("""
            INSERT INTO disponibilita_profili_categoria (
                utente_id, categoria_slug, stato_generale, confermata_at
            ) VALUES (13, 'babysitter', 'disponibile', ?)
        """, (confirmed.isoformat(),))
        conn.execute(
            "INSERT INTO acquisti VALUES (40, 'paid', 999, 'stripe')"
        )
        conn.execute("""
            INSERT INTO attivazioni_servizi VALUES (
                50, 4, 40, 'attivo', ?, ?
            )
        """, (
            (now - timedelta(days=2)).isoformat(),
            (now + timedelta(days=10)).isoformat(),
        ))
        conn.commit()
        conn.close()

        result = self._run()

        self.assertTrue(result["ok"])
        self.assertEqual(result["annunci_archiviati"], 1)
        conn = self._connect()
        try:
            self.assertEqual(
                conn.execute(
                    "SELECT stato FROM annunci WHERE id = 4"
                ).fetchone()["stato"],
                "archiviato_disponibilita",
            )
            self.assertEqual(
                conn.execute("""
                    SELECT stato FROM annunci_disponibilita_ciclo
                    WHERE annuncio_id = 4
                """).fetchone()["stato"],
                STATO_ARCHIVIATO,
            )
        finally:
            conn.close()

if __name__ == "__main__":
    unittest.main()
