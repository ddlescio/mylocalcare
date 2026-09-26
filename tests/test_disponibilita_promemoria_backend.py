import ast
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from disponibilita_servizi import (
    CATEGORIE_SERVIZI,
    GIORNI_ESCLUSIONE_FILTRO,
    GIORNI_PROMEMORIA_SCADENZA,
    GIORNI_PRIORITA_RIDOTTA,
    GIORNI_RICONFERMA,
)


ROOT = Path(__file__).resolve().parents[1]


def load_reminder_backend():
    """Carica il solo backend del job, senza inizializzare Flask e servizi."""

    wanted = {
        "_normalizza_limite_promemoria_disponibilita",
        "_disponibilita_promemoria_datetime",
        "_link_promemoria_disponibilita",
        "_disponibilita_filtro_cerca_sql",
        "_disponibilita_priorita_cerca_sql",
        "_piano_promemoria_disponibilita",
        "processa_promemoria_disponibilita",
    }
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    namespace = {
        "app": SimpleNamespace(config={
            "IS_POSTGRES": False,
            "APP_BASE_URL": "https://www.mylocalcare.it",
        }),
        "date": date,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "CATEGORIE_SERVIZI": CATEGORIE_SERVIZI,
        "GIORNI_PROMEMORIA_SCADENZA": GIORNI_PROMEMORIA_SCADENZA,
        "GIORNI_PRIORITA_RIDOTTA": GIORNI_PRIORITA_RIDOTTA,
        "GIORNI_ESCLUSIONE_FILTRO": GIORNI_ESCLUSIONE_FILTRO,
        "GIORNI_RICONFERMA": GIORNI_RICONFERMA,
        "DISPONIBILITA_PROMEMORIA_BATCH_DEFAULT": 100,
        "DISPONIBILITA_PROMEMORIA_BATCH_MAX": 1000,
        "DISPONIBILITA_PROMEMORIA_COOLDOWN_GIORNI": 3,
    }
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    return namespace


class DisponibilitaPromemoriaBackendTest(unittest.TestCase):
    def setUp(self):
        self.backend = load_reminder_backend()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "reminders.sqlite3"
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                email TEXT,
                nome TEXT,
                username TEXT,
                email_notifiche INTEGER DEFAULT 1,
                lingua_interfaccia TEXT DEFAULT 'it',
                attivo INTEGER DEFAULT 1,
                sospeso INTEGER DEFAULT 0,
                disattivato_admin INTEGER DEFAULT 0,
                eliminato INTEGER DEFAULT 0
            );
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                stato_generale TEXT NOT NULL,
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                stato_generale TEXT NOT NULL,
                confermata_at TEXT,
                ultimo_promemoria_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE notifiche (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                id_utente INTEGER NOT NULL,
                titolo TEXT,
                messaggio TEXT NOT NULL,
                link TEXT,
                tipo TEXT,
                letta INTEGER DEFAULT 0,
                data TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                tipo_annuncio TEXT,
                categoria_slug TEXT,
                categoria TEXT
            );
        """)
        conn.commit()
        conn.close()

        self.offerte = {}
        self.push_calls = []
        self.email_calls = []
        self.emit_calls = []
        self.logs = []
        self.backend.update({
            "get_db_connection": self._connect,
            "get_cursor": lambda conn: conn.cursor(),
            "sql": lambda query: query,
            "_disponibilita_servizi_table_exists": lambda cur: True,
            "_disponibilita_categoria_table_exists": lambda cur: True,
            "_categorie_disponibilita_offerte": (
                lambda cur, user_id: [
                    {"slug": slug, "label": slug}
                    for slug in self.offerte.get(int(user_id), [])
                ]
            ),
            "_schede_profilo_begin": (
                lambda cur: cur.execute("BEGIN IMMEDIATE")
            ),
            "_schede_profilo_commit": lambda cur: cur.execute("COMMIT"),
            "_schede_profilo_rollback": self._rollback,
            "normalize_language": lambda value: str(value or "it"),
            "translate_source": (
                lambda source, language: f"{source} [{language}]"
            ),
            "emit_update_notifications": self.emit_calls.append,
            "invia_push": self._push,
            "_invia_email": self._email,
            "log_exception_safe": self._log,
        })

    def tearDown(self):
        self.temp_dir.cleanup()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _rollback(cur):
        try:
            cur.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass

    def _log(self, *args, **kwargs):
        self.logs.append((args, kwargs))

    def _assert_reservation_committed(self, user_id):
        probe = self._connect()
        try:
            general = probe.execute(
                "SELECT ultimo_promemoria_at FROM disponibilita_profili "
                "WHERE utente_id = ?",
                (user_id,),
            ).fetchone()
            notification_count = probe.execute(
                "SELECT COUNT(*) FROM notifiche WHERE id_utente = ?",
                (user_id,),
            ).fetchone()[0]
            self.assertIsNotNone(general["ultimo_promemoria_at"])
            self.assertEqual(notification_count, 1)
        finally:
            probe.close()

    def _push(self, user_id, title, body, url=None):
        # Una nuova connessione vede entrambi solo se il COMMIT precede il push.
        self._assert_reservation_committed(user_id)
        self.push_calls.append((user_id, title, body, url))

    def _email(self, **kwargs):
        self._assert_reservation_committed(1)
        self.email_calls.append(kwargs)
        return True

    def test_aggregazione_lock_logico_e_filtraggio_categorie_offerte(self):
        now = datetime.now(timezone.utc)
        expired = (now - timedelta(days=45)).isoformat()
        recent = (now - timedelta(days=2)).isoformat()
        conn = self._connect()
        conn.executemany("""
            INSERT INTO utenti (
                id, email, nome, username, email_notifiche,
                lingua_interfaccia, attivo, sospeso,
                disattivato_admin, eliminato
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (1, "uno@example.test", "Uno", "UNO", 1, "en", 1, 0, 0, 0),
            (2, "due@example.test", "Due", "DUE", 1, "it", 1, 1, 0, 0),
        ])
        conn.executemany("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at,
                ultimo_promemoria_at, versione
            ) VALUES (?, ?, ?, NULL, ?)
        """, [
            (1, "limitata", expired, 8),
            (2, "disponibile", expired, 3),
        ])
        conn.executemany("""
            INSERT INTO disponibilita_profili_categoria (
                id, utente_id, categoria_slug, stato_generale,
                confermata_at, ultimo_promemoria_at, versione
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [
            (10, 1, "babysitter", "disponibile", expired, None, 4),
            # Non e piu offerta: il suo reminder recente non deve bloccare.
            (11, 1, "pet-sitter", "non_disponibile", expired, recent, 6),
        ])
        conn.commit()
        conn.close()
        self.offerte = {1: ["babysitter"], 2: ["caregiver"]}

        result = self.backend["processa_promemoria_disponibilita"](
            limite=25,
            dry_run=False,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["utenti_prenotati"], 1)
        self.assertEqual(result["notifiche_create"], 1)
        self.assertEqual(result["push_tentate"], 1)
        self.assertEqual(result["email_inviate"], 1)
        self.assertEqual(len(self.push_calls), 1)
        self.assertEqual(len(self.email_calls), 1)
        self.assertEqual(self.emit_calls, [1])
        self.assertEqual(
            self.push_calls[0][1],
            "Ultimo avviso: rinnova la disponibilità [en]",
        )
        self.assertEqual(
            self.push_calls[0][2],
            "La tua disponibilità è scaduta da 7 giorni e la priorità "
            "dei tuoi annunci è stata ridotta. Riconfermala ora per "
            "ripristinarla. [en]",
        )
        # Generale e categoria sono alla stessa fase: il link deve aprire la
        # riconferma generale, non una categoria scelta arbitrariamente.
        expected_link = "/utente/dashboard?disponibilita=riconferma"
        self.assertEqual(self.push_calls[0][3], expected_link)
        self.assertEqual(
            self.email_calls[0]["action_url"],
            f"https://www.mylocalcare.it{expected_link}",
        )
        self.assertEqual(
            self.email_calls[0]["oggetto"],
            "Ultimo avviso: rinnova la disponibilità",
        )
        self.assertEqual(
            self.email_calls[0]["action_label"],
            "Controlla disponibilità",
        )

        check = self._connect()
        general = check.execute(
            "SELECT * FROM disponibilita_profili WHERE utente_id = 1"
        ).fetchone()
        offered = check.execute(
            "SELECT * FROM disponibilita_profili_categoria WHERE id = 10"
        ).fetchone()
        removed = check.execute(
            "SELECT * FROM disponibilita_profili_categoria WHERE id = 11"
        ).fetchone()
        suspended_notifications = check.execute(
            "SELECT COUNT(*) FROM notifiche WHERE id_utente = 2"
        ).fetchone()[0]
        check.close()
        self.assertEqual(general["stato_generale"], "limitata")
        self.assertEqual(general["versione"], 8)
        self.assertIsNotNone(general["ultimo_promemoria_at"])
        self.assertEqual(offered["stato_generale"], "disponibile")
        self.assertEqual(offered["versione"], 4)
        self.assertIsNotNone(offered["ultimo_promemoria_at"])
        self.assertEqual(removed["ultimo_promemoria_at"], recent)
        self.assertEqual(suspended_notifications, 0)

        # La stessa fase non viene mai inviata due volte nello stesso ciclo.
        second = self.backend["processa_promemoria_disponibilita"](
            limite=25,
            dry_run=False,
        )
        self.assertEqual(second["utenti_prenotati"], 0)
        self.assertEqual(len(self.push_calls), 1)
        self.assertEqual(len(self.email_calls), 1)

    def test_dry_run_non_modifica_e_rispetta_limite(self):
        expired = (
            datetime.now(timezone.utc) - timedelta(days=40)
        ).isoformat()
        conn = self._connect()
        for user_id in (3, 4):
            conn.execute("""
                INSERT INTO utenti (
                    id, email, username, email_notifiche, attivo,
                    sospeso, disattivato_admin, eliminato
                ) VALUES (?, ?, ?, 1, 1, 0, 0, 0)
            """, (user_id, f"u{user_id}@example.test", f"U{user_id}"))
            conn.execute("""
                INSERT INTO disponibilita_profili (
                    utente_id, stato_generale, confermata_at,
                    ultimo_promemoria_at, versione
                ) VALUES (?, 'disponibile', ?, NULL, 1)
            """, (user_id, expired))
        conn.commit()
        conn.close()
        self.offerte = {3: ["caregiver"], 4: ["babysitter"]}

        result = self.backend["processa_promemoria_disponibilita"](
            limite=1,
            dry_run=True,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["utenti_da_notificare"], 1)
        self.assertEqual(result["utenti_prenotati"], 0)
        self.assertEqual(self.push_calls, [])
        self.assertEqual(self.email_calls, [])
        check = self._connect()
        self.assertEqual(
            check.execute("SELECT COUNT(*) FROM notifiche").fetchone()[0],
            0,
        )
        self.assertEqual(
            check.execute("""
                SELECT COUNT(*) FROM disponibilita_profili
                WHERE ultimo_promemoria_at IS NOT NULL
            """).fetchone()[0],
            0,
        )
        check.close()

    def test_fasi_progressive_e_deduplicazione_per_ciclo(self):
        now = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
        planner = self.backend["_piano_promemoria_disponibilita"]

        def plan(days, last=None):
            return planner(
                {
                    "id": 1,
                    "confermata_at": now - timedelta(days=days),
                    "ultimo_promemoria_at": last,
                },
                [],
                ["babysitter"],
                adesso=now,
            )

        self.assertIsNone(plan(24))

        warning = plan(25)
        self.assertEqual(warning["fase"], "in_scadenza")
        self.assertTrue(warning["aggiorna_generale"])

        warning_sent_at = now - timedelta(days=5)
        renewal = plan(30, warning_sent_at)
        self.assertEqual(renewal["fase"], "scaduta")

        renewal_sent_at = now - timedelta(days=7)
        final = plan(37, renewal_sent_at)
        self.assertEqual(final["fase"], "ultimo_avviso")

        final_sent_at = now - timedelta(days=7)
        self.assertIsNone(plan(44, final_sent_at))

    def test_priorita_organica_scende_a_37_giorni_con_override_categoria(self):
        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(days=10)).isoformat()
        stale = (now - timedelta(days=40)).isoformat()
        conn = self._connect()
        conn.executemany(
            """
            INSERT INTO annunci (
                id, utente_id, tipo_annuncio, categoria
            ) VALUES (?, ?, ?, ?)
            """,
            [
                (1, 1, "offro", "babysitter"),
                (2, 2, "offro", "babysitter"),
                (3, 3, "offro", "babysitter"),
                (4, 4, "offro", "babysitter"),
                (5, 5, "offro", "babysitter"),
                # Stesse disponibilita fresche degli annunci 1 e 4, ma un
                # annuncio cerco non deve mai ricevere questo vantaggio.
                (6, 1, "cerco", "babysitter"),
                (7, 4, "cerco", "babysitter"),
            ],
        )
        conn.executemany("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at,
                ultimo_promemoria_at, versione
            ) VALUES (?, 'disponibile', ?, NULL, 1)
        """, [
            (1, fresh),
            (2, stale),
            (3, fresh),
            (4, stale),
        ])
        conn.executemany("""
            INSERT INTO disponibilita_profili_categoria (
                id, utente_id, categoria_slug, stato_generale,
                confermata_at, ultimo_promemoria_at, versione
            ) VALUES (?, ?, 'babysitter', 'disponibile', ?, NULL, 1)
        """, [
            (30, 3, stale),
            (40, 4, fresh),
        ])
        conn.commit()
        expression = self.backend["_disponibilita_priorita_cerca_sql"](
            conn.cursor()
        )
        rows = conn.execute(f"""
            SELECT a.id, a.utente_id, a.tipo_annuncio, ({expression}) AS score
            FROM annunci a
            ORDER BY a.id
        """).fetchall()
        conn.close()

        self.assertEqual(
            {int(row["id"]): int(row["score"]) for row in rows},
            {1: 1, 2: 0, 3: 0, 4: 1, 5: 0, 6: 0, 7: 0},
        )

    def test_priorita_disponibilita_solo_offro_anche_senza_override_categoria(
        self,
    ):
        fresh = (
            datetime.now(timezone.utc) - timedelta(days=10)
        ).isoformat()
        conn = self._connect()
        conn.executemany(
            """
            INSERT INTO annunci (
                id, utente_id, tipo_annuncio, categoria
            ) VALUES (?, ?, ?, 'babysitter')
            """,
            [
                (21, 21, "offro"),
                (22, 22, "cerco"),
                (23, 23, None),
            ],
        )
        conn.executemany(
            """
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at,
                ultimo_promemoria_at, versione
            ) VALUES (?, 'disponibile', ?, NULL, 1)
            """,
            [(21, fresh), (22, fresh), (23, fresh)],
        )
        conn.commit()

        self.backend["_disponibilita_categoria_table_exists"] = (
            lambda cur: False
        )
        expression = self.backend["_disponibilita_priorita_cerca_sql"](
            conn.cursor()
        )
        rows = conn.execute(f"""
            SELECT a.id, ({expression}) AS score
            FROM annunci a
            WHERE a.id IN (21, 22, 23)
            ORDER BY a.id
        """).fetchall()
        conn.close()

        self.assertEqual(
            {int(row["id"]): int(row["score"]) for row in rows},
            {21: 1, 22: 0, 23: 0},
        )

    def test_filtro_disponibili_esclude_oltre_44_giorni_e_rispetta_override(self):
        now = datetime.now(timezone.utc)
        fresh = (now - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        stale = (now - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        conn.executemany(
            "INSERT INTO annunci (id, utente_id, categoria) VALUES (?, ?, ?)",
            [
                (11, 11, "babysitter"),
                (12, 12, "babysitter"),
                (13, 13, "babysitter"),
                (14, 14, "babysitter"),
                (15, 15, "babysitter"),
            ],
        )
        conn.executemany("""
            INSERT INTO disponibilita_profili (
                utente_id, stato_generale, confermata_at,
                ultimo_promemoria_at, versione
            ) VALUES (?, 'disponibile', ?, NULL, 1)
        """, [
            (11, fresh),
            (12, stale),
            (13, fresh),
            (14, stale),
        ])
        conn.executemany("""
            INSERT INTO disponibilita_profili_categoria (
                id, utente_id, categoria_slug, stato_generale,
                confermata_at, ultimo_promemoria_at, versione
            ) VALUES (?, ?, 'babysitter', ?, ?, NULL, 1)
        """, [
            (130, 13, "non_disponibile", fresh),
            (140, 14, "disponibile", fresh),
        ])
        conn.commit()

        expression = self.backend["_disponibilita_filtro_cerca_sql"](
            conn.cursor()
        )
        rows = conn.execute(f"""
            SELECT a.utente_id
            FROM annunci a
            WHERE ({expression})
            ORDER BY a.utente_id
        """).fetchall()
        conn.close()

        self.assertEqual([int(row["utente_id"]) for row in rows], [11, 14])

    def test_un_promemoria_recente_di_altro_profilo_non_blocca(self):
        now = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
        expired = now - timedelta(days=31)
        recent = now - timedelta(days=3)
        planner = self.backend["_piano_promemoria_disponibilita"]

        allowed_with_fresh_category = planner(
            {
                "id": 1,
                "confermata_at": expired,
                "ultimo_promemoria_at": None,
            },
            [{
                "id": 7,
                "categoria_slug": "babysitter",
                "confermata_at": now - timedelta(days=2),
                "ultimo_promemoria_at": recent,
            }],
            ["babysitter"],
            adesso=now,
        )
        self.assertIsNotNone(allowed_with_fresh_category)
        self.assertEqual(allowed_with_fresh_category["fase"], "scaduta")
        self.assertTrue(allowed_with_fresh_category["aggiorna_generale"])
        self.assertEqual(
            allowed_with_fresh_category["profili_categoria_ids"],
            [],
        )

        allowed = planner(
            {
                "id": 1,
                "confermata_at": expired,
                "ultimo_promemoria_at": None,
            },
            [{
                "id": 8,
                "categoria_slug": "pet-sitter",
                "confermata_at": expired,
                "ultimo_promemoria_at": recent,
            }],
            ["babysitter"],
            adesso=now,
        )
        self.assertIsNotNone(allowed)
        self.assertEqual(allowed["fase"], "scaduta")
        self.assertEqual(allowed["profili_categoria_ids"], [])
        self.assertEqual(
            self.backend["_link_promemoria_disponibilita"]("babysitter"),
            "/utente/dashboard?disponibilita=riconferma&categoria=babysitter",
        )
        self.assertEqual(
            self.backend["_link_promemoria_disponibilita"]("non-valida"),
            "/utente/dashboard?disponibilita=riconferma",
        )

    def test_profili_sfalsati_non_generano_promemoria_consecutivi(self):
        now = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
        planner = self.backend["_piano_promemoria_disponibilita"]
        generale_confermata = now - timedelta(days=25)
        categoria_confermata = now - timedelta(days=24)

        primo = planner(
            {
                "id": 1,
                "confermata_at": generale_confermata,
                "ultimo_promemoria_at": None,
            },
            [{
                "id": 7,
                "categoria_slug": "babysitter",
                "confermata_at": categoria_confermata,
                "ultimo_promemoria_at": None,
            }],
            ["babysitter"],
            adesso=now,
        )
        self.assertEqual(primo["fase"], "in_scadenza")
        self.assertIsNone(primo["categoria_link"])
        self.assertTrue(primo["aggiorna_generale"])
        self.assertEqual(primo["profili_categoria_ids"], [])

        # Il giorno successivo matura la categoria, ma non parte un secondo
        # avviso consecutivo. La fase resta dovuta, perche il relativo
        # timestamp non viene aggiornato durante il cooldown.
        giorno_successivo = now + timedelta(days=1)
        bloccato = planner(
            {
                "id": 1,
                "confermata_at": generale_confermata,
                "ultimo_promemoria_at": now,
            },
            [{
                "id": 7,
                "categoria_slug": "babysitter",
                "confermata_at": categoria_confermata,
                "ultimo_promemoria_at": None,
            }],
            ["babysitter"],
            adesso=giorno_successivo,
        )
        self.assertIsNone(bloccato)

        # Scaduto l'intervallo minimo, la categoria viene recuperata e il
        # deep-link apre esattamente quella scheda.
        dopo_cooldown = now + timedelta(days=3)
        recuperato = planner(
            {
                "id": 1,
                "confermata_at": generale_confermata,
                "ultimo_promemoria_at": now,
            },
            [{
                "id": 7,
                "categoria_slug": "babysitter",
                "confermata_at": categoria_confermata,
                "ultimo_promemoria_at": None,
            }],
            ["babysitter"],
            adesso=dopo_cooldown,
        )
        self.assertEqual(recuperato["fase"], "in_scadenza")
        self.assertEqual(recuperato["categoria_link"], "babysitter")
        self.assertFalse(recuperato["aggiorna_generale"])
        self.assertEqual(recuperato["profili_categoria_ids"], [7])

    def test_fase_piu_urgente_supera_il_cooldown_multi_profilo(self):
        now = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
        planner = self.backend["_piano_promemoria_disponibilita"]

        plan = planner(
            {
                "id": 1,
                "confermata_at": now - timedelta(days=30),
                # Il preavviso e partito ieri: la scadenza odierna non deve
                # essere persa a causa dell'antispam.
                "ultimo_promemoria_at": now - timedelta(days=1),
            },
            [{
                "id": 8,
                "categoria_slug": "pet-sitter",
                "confermata_at": now - timedelta(days=26),
                "ultimo_promemoria_at": now - timedelta(days=1),
            }],
            ["pet-sitter"],
            adesso=now,
        )

        self.assertEqual(plan["fase"], "scaduta")
        self.assertIsNone(plan["categoria_link"])
        self.assertTrue(plan["aggiorna_generale"])
        self.assertEqual(plan["profili_categoria_ids"], [])


if __name__ == "__main__":
    unittest.main()
