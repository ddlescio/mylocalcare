import ast
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from disponibilita_servizi import CATEGORIE_SERVIZI, GIORNI_RICONFERMA


ROOT = Path(__file__).resolve().parents[1]


def load_reminder_backend():
    """Carica il solo backend del job, senza inizializzare Flask e servizi."""

    wanted = {
        "_normalizza_limite_promemoria_disponibilita",
        "_disponibilita_promemoria_datetime",
        "_link_promemoria_disponibilita",
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
        "GIORNI_RICONFERMA": GIORNI_RICONFERMA,
        "DISPONIBILITA_PROMEMORIA_BATCH_DEFAULT": 100,
        "DISPONIBILITA_PROMEMORIA_BATCH_MAX": 1000,
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
            "Riconferma la tua disponibilità [en]",
        )
        self.assertEqual(
            self.push_calls[0][2],
            "È passato circa un mese dall’ultima conferma. Controlla i dati "
            "già salvati: puoi riconfermarli così come sono oppure "
            "modificarli. [en]",
        )
        expected_link = (
            "/utente/dashboard?disponibilita=riconferma&categoria=babysitter"
        )
        self.assertEqual(self.push_calls[0][3], expected_link)
        self.assertEqual(
            self.email_calls[0]["action_url"],
            f"https://www.mylocalcare.it{expected_link}",
        )
        self.assertEqual(
            self.email_calls[0]["oggetto"],
            "Riconferma la tua disponibilità su MyLocalCare",
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

        # Una seconda esecuzione entro 30 giorni non crea ne invia nulla.
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

    def test_throttle_e_link_sono_per_utente(self):
        now = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
        expired = now - timedelta(days=31)
        recent = now - timedelta(days=3)
        planner = self.backend["_piano_promemoria_disponibilita"]

        blocked = planner(
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
        self.assertIsNone(blocked)

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
        self.assertEqual(allowed["profili_categoria_ids"], [])
        self.assertEqual(
            self.backend["_link_promemoria_disponibilita"]("babysitter"),
            "/utente/dashboard?disponibilita=riconferma&categoria=babysitter",
        )
        self.assertEqual(
            self.backend["_link_promemoria_disponibilita"]("non-valida"),
            "/utente/dashboard?disponibilita=riconferma",
        )


if __name__ == "__main__":
    unittest.main()
