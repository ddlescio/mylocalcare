import ast
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from richieste_disponibilita import (
    GIORNI_SCADENZA_RICHIESTA,
    normalize_richiesta_disponibilita_payload,
    normalizza_stato_richiesta_disponibilita,
    valida_limiti_anti_abuso,
)


ROOT = Path(__file__).resolve().parents[1]


def _url_for(endpoint, **values):
    if endpoint == "visualizza_annuncio_pubblico":
        path = f"/annuncio/{values['id']}"
        request_id = values.get("richiesta_disponibilita")
        return (
            f"{path}?richiesta_disponibilita={request_id}"
            if request_id is not None
            else path
        )
    if endpoint == "profilo_pubblico":
        return f"/profilo/{values['id']}"
    if endpoint == "static":
        return f"/static/{values['filename']}"
    if endpoint == "chat_conversazione_view":
        path = f"/chat/{values['other_id']}"
        request_id = values.get("richiesta_disponibilita")
        return (
            f"{path}?richiesta_disponibilita={request_id}"
            if request_id is not None
            else path
        )
    raise AssertionError(endpoint)


def load_request_backend():
    wanted_functions = {
        "_disponibilita_promemoria_datetime",
        "_richiesta_disponibilita_account_attivo",
        "_richiesta_disponibilita_time",
        "_richiesta_disponibilita_bloccata",
        "_link_richiesta_disponibilita",
        "_link_risposta_disponibilita",
        "_inserisci_notifica_richiesta_disponibilita",
        "_prenota_richiesta_disponibilita",
        "_prenota_risposta_disponibilita",
        "_invia_canali_richiesta_disponibilita",
        "_elenca_richieste_disponibilita_chat",
    }
    wanted_constants = {
        "RICHIESTA_DISPONIBILITA_TITOLO",
        "RICHIESTA_DISPONIBILITA_MESSAGGIO",
        "RICHIESTA_DISPONIBILITA_EMAIL_OGGETTO",
        "RICHIESTA_DISPONIBILITA_EMAIL_CTA",
        "RISPOSTA_DISPONIBILITA_TITOLO",
        "RISPOSTA_DISPONIBILITA_MESSAGGI",
        "RISPOSTA_DISPONIBILITA_EMAIL_OGGETTO",
        "RISPOSTA_DISPONIBILITA_EMAIL_CTA",
    }
    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    selected = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == (
            "RichiestaDisponibilitaError"
        ):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in wanted_functions:
            selected.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            names = {
                target.id
                for target in getattr(node, "targets", [])
                if isinstance(target, ast.Name)
            }
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
            if names & wanted_constants:
                selected.append(node)

    def insert_and_get_id(cursor, query, params):
        cursor.execute(query, params)
        return cursor.lastrowid

    namespace = {
        "app": SimpleNamespace(config={
            "IS_POSTGRES": False,
            "APP_BASE_URL": "https://www.mylocalcare.it",
        }),
        "date": date,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "GIORNI_SCADENZA_RICHIESTA": GIORNI_SCADENZA_RICHIESTA,
        "normalize_richiesta_disponibilita_payload": (
            normalize_richiesta_disponibilita_payload
        ),
        "normalizza_stato_richiesta_disponibilita": (
            normalizza_stato_richiesta_disponibilita
        ),
        "valida_limiti_anti_abuso": valida_limiti_anti_abuso,
        "sql": lambda query: query,
        "insert_and_get_id": insert_and_get_id,
        "normalize_language": lambda value: str(value or "it"),
        "translate_source": (
            lambda source, language: f"{source} [{language}]"
        ),
        "url_for": _url_for,
        "_scheda_profilo_bool": lambda value: bool(value),
        "_scheda_profilo_iso": (
            lambda value: value.isoformat()
            if hasattr(value, "isoformat")
            else ("" if value is None else str(value))
        ),
        "_richieste_disponibilita_tables_exist": lambda cur: True,
        "emit_update_notifications": lambda user_id: None,
        "invia_push": lambda *args, **kwargs: None,
        "_invia_email": lambda **kwargs: True,
        "log_exception_safe": lambda *args, **kwargs: None,
    }
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    return namespace


class RichiestaDisponibilitaBackendTest(unittest.TestCase):
    def setUp(self):
        self.backend = load_request_backend()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "requests.sqlite3"
        conn = self.connect()
        conn.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                username TEXT,
                nome TEXT,
                cognome TEXT,
                email TEXT,
                email_notifiche INTEGER DEFAULT 1,
                lingua_interfaccia TEXT DEFAULT 'it',
                citta TEXT,
                provincia TEXT,
                foto_profilo TEXT,
                attivo INTEGER DEFAULT 1,
                sospeso INTEGER DEFAULT 0,
                disattivato_admin INTEGER DEFAULT 0,
                eliminato INTEGER DEFAULT 0,
                ruolo TEXT DEFAULT 'user'
            );
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                titolo TEXT,
                categoria TEXT,
                tipo_annuncio TEXT,
                stato TEXT
            );
            CREATE TABLE chat_blocchi (
                bloccante_id INTEGER NOT NULL,
                bloccato_id INTEGER NOT NULL
            );
            CREATE TABLE richieste_disponibilita (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                annuncio_id INTEGER NOT NULL,
                richiedente_id INTEGER NOT NULL,
                offerente_id INTEGER NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                stato TEXT NOT NULL DEFAULT 'in_attesa',
                risposta_at TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX ux_request_pending
                ON richieste_disponibilita (annuncio_id, richiedente_id)
                WHERE stato = 'in_attesa';
            CREATE TABLE richieste_disponibilita_fasce (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                richiesta_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                fascia TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE richieste_disponibilita_intervalli (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                richiesta_id INTEGER NOT NULL,
                giorno_settimana INTEGER NOT NULL,
                ora_inizio TEXT NOT NULL,
                ora_fine TEXT NOT NULL,
                giorno_successivo INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE notifiche (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                id_utente INTEGER NOT NULL,
                titolo TEXT,
                messaggio TEXT NOT NULL,
                link TEXT,
                tipo TEXT,
                letta INTEGER DEFAULT 0
            );
        """)
        conn.executemany("""
            INSERT INTO utenti (
                id, username, nome, email, email_notifiche,
                lingua_interfaccia, citta, provincia, foto_profilo,
                attivo, sospeso, disattivato_admin, eliminato, ruolo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0, 0, 'user')
        """, [
            (1, "RICHIEDENTE", "Rita", "rita@example.test", 1, "en",
             "Milano", "Milano", "rita.jpg"),
            (2, "OFFERENTE", "Olga", "olga@example.test", 1, "fr",
             "Roma", "Roma", "olga.jpg"),
            (3, "ESTERNO", "Erica", "erica@example.test", 1, "it",
             "Torino", "Torino", "erica.jpg"),
        ])
        conn.execute("""
            INSERT INTO annunci (
                id, utente_id, titolo, categoria, tipo_annuncio, stato
            ) VALUES (
                10, 2, 'Babysitter', 'Babysitter', 'offro', 'approvato'
            )
        """)
        conn.commit()
        conn.close()

    def tearDown(self):
        self.temp_dir.cleanup()

    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def calendar():
        return normalize_richiesta_disponibilita_payload({
            "giorni": [{
                "giorno_settimana": 2,
                "fasce": ["mattina"],
                "intervalli": [{
                    "ora_inizio": "15:00",
                    "ora_fine": "18:00",
                    "giorno_successivo": False,
                }],
            }],
        })

    def create_request(self, *, now=None):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        dispatch = self.backend["_prenota_richiesta_disponibilita"](
            cur,
            annuncio_id=10,
            richiedente_id=1,
            calendario=self.calendar(),
            adesso=now or datetime(2026, 9, 25, 10, tzinfo=timezone.utc),
        )
        cur.execute("COMMIT")
        conn.close()
        return dispatch

    def test_creazione_persistente_con_figli_e_una_notifica_localizzata(self):
        dispatch = self.create_request()

        conn = self.connect()
        request_row = conn.execute(
            "SELECT * FROM richieste_disponibilita"
        ).fetchone()
        slots = conn.execute(
            "SELECT giorno_settimana, fascia "
            "FROM richieste_disponibilita_fasce"
        ).fetchall()
        intervals = conn.execute(
            "SELECT giorno_settimana, ora_inizio, ora_fine "
            "FROM richieste_disponibilita_intervalli"
        ).fetchall()
        notifications = conn.execute(
            "SELECT * FROM notifiche WHERE id_utente = 2"
        ).fetchall()
        conn.close()

        self.assertEqual(request_row["stato"], "in_attesa")
        self.assertEqual(request_row["a_chiamata"], 0)
        self.assertEqual([(row[0], row[1]) for row in slots], [(2, "mattina")])
        self.assertEqual(
            [(row[0], row[1], row[2]) for row in intervals],
            [(2, "15:00", "18:00")],
        )
        self.assertEqual(len(notifications), 1)
        self.assertTrue(notifications[0]["titolo"].endswith("[fr]"))
        self.assertEqual(
            notifications[0]["link"],
            f"/chat/1?richiesta_disponibilita={dispatch['richiesta_id']}",
        )

    def test_creazione_a_chiamata_senza_giorni(self):
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        dispatch = self.backend["_prenota_richiesta_disponibilita"](
            cur,
            annuncio_id=10,
            richiedente_id=1,
            calendario={"a_chiamata": True, "giorni": []},
            adesso=datetime(2026, 9, 25, 10, tzinfo=timezone.utc),
        )
        cur.execute("COMMIT")
        row = conn.execute(
            "SELECT a_chiamata FROM richieste_disponibilita WHERE id = ?",
            (dispatch["richiesta_id"],),
        ).fetchone()
        child_count = conn.execute("""
            SELECT (
                SELECT COUNT(*) FROM richieste_disponibilita_fasce
            ) + (
                SELECT COUNT(*) FROM richieste_disponibilita_intervalli
            )
        """).fetchone()[0]
        conn.close()

        self.assertEqual(row["a_chiamata"], 1)
        self.assertEqual(child_count, 0)

    def test_blocco_bidirezionale_impedisce_creazione(self):
        for blocker, blocked in ((1, 2), (2, 1)):
            with self.subTest(blocker=blocker):
                conn = self.connect()
                conn.execute("DELETE FROM chat_blocchi")
                conn.execute(
                    "INSERT INTO chat_blocchi VALUES (?, ?)",
                    (blocker, blocked),
                )
                conn.commit()
                cur = conn.cursor()
                cur.execute("BEGIN IMMEDIATE")
                with self.assertRaisesRegex(
                    self.backend["RichiestaDisponibilitaError"],
                    "Non è possibile",
                ):
                    self.backend["_prenota_richiesta_disponibilita"](
                        cur,
                        annuncio_id=10,
                        richiedente_id=1,
                        calendario=self.calendar(),
                    )
                cur.execute("ROLLBACK")
                conn.close()

    def test_self_account_inattivo_e_non_owner_sono_rifiutati(self):
        conn = self.connect()
        conn.execute("UPDATE annunci SET utente_id = 1 WHERE id = 10")
        conn.commit()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        with self.assertRaises(
            self.backend["RichiestaDisponibilitaError"]
        ) as self_error:
            self.backend["_prenota_richiesta_disponibilita"](
                cur,
                annuncio_id=10,
                richiedente_id=1,
                calendario=self.calendar(),
            )
        self.assertEqual(self_error.exception.code, "self_request")
        cur.execute("ROLLBACK")

        conn.execute("UPDATE annunci SET utente_id = 2 WHERE id = 10")
        conn.execute("UPDATE utenti SET attivo = 0 WHERE id = 1")
        conn.commit()
        cur.execute("BEGIN IMMEDIATE")
        with self.assertRaises(
            self.backend["RichiestaDisponibilitaError"]
        ) as account_error:
            self.backend["_prenota_richiesta_disponibilita"](
                cur,
                annuncio_id=10,
                richiedente_id=1,
                calendario=self.calendar(),
            )
        self.assertEqual(account_error.exception.code, "account_unavailable")
        cur.execute("ROLLBACK")
        conn.execute("UPDATE utenti SET attivo = 1 WHERE id = 1")
        conn.commit()
        conn.close()

        dispatch = self.create_request()
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        with self.assertRaises(
            self.backend["RichiestaDisponibilitaError"]
        ) as owner_error:
            self.backend["_prenota_risposta_disponibilita"](
                cur,
                richiesta_id=dispatch["richiesta_id"],
                offerente_id=1,
                stato="disponibile",
                versione=1,
            )
        self.assertEqual(owner_error.exception.code, "not_found")
        cur.execute("ROLLBACK")
        conn.close()

    def test_scadenza_libera_pending_e_consente_nuova_richiesta(self):
        now = datetime(2026, 9, 25, 10, tzinfo=timezone.utc)
        old = now - timedelta(days=GIORNI_SCADENZA_RICHIESTA, minutes=1)
        conn = self.connect()
        conn.execute("""
            INSERT INTO richieste_disponibilita (
                annuncio_id, richiedente_id, offerente_id, stato,
                risposta_at, versione, created_at, updated_at
            ) VALUES (10, 1, 2, 'in_attesa', NULL, 1, ?, ?)
        """, (old, old))
        conn.commit()
        conn.close()

        dispatch = self.create_request(now=now)
        conn = self.connect()
        rows = conn.execute("""
            SELECT id, stato, risposta_at, versione
            FROM richieste_disponibilita ORDER BY id
        """).fetchall()
        conn.close()
        self.assertEqual([row["stato"] for row in rows], ["scaduta", "in_attesa"])
        self.assertIsNotNone(rows[0]["risposta_at"])
        self.assertEqual(rows[0]["versione"], 2)
        self.assertEqual(rows[1]["id"], dispatch["richiesta_id"])

    def test_risposta_e_atomica_versionata_e_non_ripetibile(self):
        dispatch = self.create_request()
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        answer = self.backend["_prenota_risposta_disponibilita"](
            cur,
            richiesta_id=dispatch["richiesta_id"],
            offerente_id=2,
            stato="informazioni",
            versione=1,
            adesso=datetime(2026, 9, 25, 11, tzinfo=timezone.utc),
        )
        cur.execute("COMMIT")
        row = conn.execute(
            "SELECT stato, versione, risposta_at FROM richieste_disponibilita"
        ).fetchone()
        notices = conn.execute(
            "SELECT COUNT(*) FROM notifiche WHERE id_utente = 1"
        ).fetchone()[0]
        self.assertEqual(row["stato"], "informazioni")
        self.assertEqual(row["versione"], 2)
        self.assertIsNotNone(row["risposta_at"])
        self.assertEqual(answer["versione"], 2)
        self.assertEqual(
            answer["link"],
            f"/chat/2?richiesta_disponibilita={dispatch['richiesta_id']}",
        )
        self.assertEqual(notices, 1)

        cur.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(
            self.backend["RichiestaDisponibilitaError"],
            "già ricevuto",
        ):
            self.backend["_prenota_risposta_disponibilita"](
                cur,
                richiesta_id=dispatch["richiesta_id"],
                offerente_id=2,
                stato="disponibile",
                versione=1,
            )
        cur.execute("ROLLBACK")
        conn.close()

    def test_blocco_sopravvenuto_impedisce_risposta_e_notifica(self):
        dispatch = self.create_request()
        conn = self.connect()
        conn.execute("INSERT INTO chat_blocchi VALUES (2, 1)")
        conn.commit()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(
            self.backend["RichiestaDisponibilitaError"],
            "non è più disponibile",
        ):
            self.backend["_prenota_risposta_disponibilita"](
                cur,
                richiesta_id=dispatch["richiesta_id"],
                offerente_id=2,
                stato="disponibile",
                versione=1,
            )
        cur.execute("ROLLBACK")
        self.assertEqual(
            conn.execute(
                "SELECT stato FROM richieste_disponibilita"
            ).fetchone()[0],
            "in_attesa",
        )
        self.assertEqual(
            conn.execute(
                "SELECT COUNT(*) FROM notifiche WHERE id_utente = 1"
            ).fetchone()[0],
            0,
        )
        conn.close()

    def test_risposta_a_richiesta_oltre_sette_giorni_la_chiude_scaduta(self):
        now = datetime(2026, 9, 25, 10, tzinfo=timezone.utc)
        old = now - timedelta(days=GIORNI_SCADENZA_RICHIESTA, seconds=1)
        conn = self.connect()
        cursor = conn.execute("""
            INSERT INTO richieste_disponibilita (
                annuncio_id, richiedente_id, offerente_id, stato,
                risposta_at, versione, created_at, updated_at
            ) VALUES (10, 1, 2, 'in_attesa', NULL, 1, ?, ?)
        """, (old, old))
        request_id = cursor.lastrowid
        conn.commit()
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        with self.assertRaises(
            self.backend["RichiestaDisponibilitaError"]
        ) as raised:
            self.backend["_prenota_risposta_disponibilita"](
                cur,
                richiesta_id=request_id,
                offerente_id=2,
                stato="disponibile",
                versione=1,
                adesso=now,
            )
        self.assertTrue(raised.exception.commit_changes)
        cur.execute("COMMIT")
        row = conn.execute("""
            SELECT stato, versione, risposta_at
            FROM richieste_disponibilita WHERE id = ?
        """, (request_id,)).fetchone()
        conn.close()
        self.assertEqual(row["stato"], "scaduta")
        self.assertEqual(row["versione"], 2)
        self.assertIsNotNone(row["risposta_at"])

    def test_lista_chat_limita_alla_coppia_e_include_storico_bidirezionale(self):
        now = datetime.now(timezone.utc)
        conn = self.connect()
        conn.execute("""
            INSERT INTO annunci (
                id, utente_id, titolo, categoria, tipo_annuncio, stato
            ) VALUES (
                12, 1, 'Aiuto compiti', 'Ripetizioni', 'offro', 'approvato'
            )
        """)
        rows_to_insert = (
            # Richiesta corrente inviata da 1 a 2.
            (10, 1, 2, 1, "in_attesa", None, now, now),
            # Storico della stessa coppia.
            (
                10, 1, 2, 0, "disponibile", now - timedelta(hours=2),
                now - timedelta(hours=3), now - timedelta(hours=2),
            ),
            # Storico nella direzione opposta, su annuncio di 1.
            (
                12, 2, 1, 0, "non_disponibile", now - timedelta(hours=4),
                now - timedelta(hours=5), now - timedelta(hours=4),
            ),
            # Richiesta estranea: non deve trapelare nella chat 1 <-> 2.
            (
                10, 3, 2, 0, "disponibile", now - timedelta(minutes=30),
                now - timedelta(hours=1), now - timedelta(minutes=30),
            ),
        )
        conn.executemany("""
            INSERT INTO richieste_disponibilita (
                annuncio_id, richiedente_id, offerente_id, a_chiamata,
                stato, risposta_at, versione, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        """, rows_to_insert)
        conn.commit()

        cards = self.backend["_elenca_richieste_disponibilita_chat"](
            conn.cursor(),
            1,
            2,
        )
        conn.close()

        self.assertEqual(len(cards), 3)
        self.assertEqual(
            {(card["richiedente_id"], card["offerente_id"]) for card in cards},
            {(1, 2), (2, 1)},
        )
        self.assertNotIn(3, {
            card["richiedente_id"] for card in cards
        } | {
            card["offerente_id"] for card in cards
        })
        pending = next(card for card in cards if card["stato"] == "in_attesa")
        self.assertTrue(pending["a_chiamata"])
        self.assertTrue(pending["inviata_da_me"])
        self.assertFalse(pending["sono_offerente"])
        self.assertFalse(pending["posso_rispondere"])
        self.assertEqual(pending["annuncio"]["categoria"], "Babysitter")
        self.assertEqual(pending["annuncio"]["url"], "/annuncio/10")
        serialized = repr(cards).lower()
        self.assertNotIn("rita@example.test", serialized)
        self.assertNotIn("erica@example.test", serialized)
        self.assertNotIn("telefono", serialized)

    def test_lista_chat_marca_pending_scaduta_e_limita_lo_storico(self):
        now = datetime.now(timezone.utc)
        conn = self.connect()
        old_pending = now - timedelta(days=GIORNI_SCADENZA_RICHIESTA, minutes=1)
        conn.execute("""
            INSERT INTO richieste_disponibilita (
                annuncio_id, richiedente_id, offerente_id, a_chiamata,
                stato, risposta_at, versione, created_at, updated_at
            ) VALUES (10, 1, 2, 1, 'in_attesa', NULL, 1, ?, ?)
        """, (old_pending, old_pending))
        conn.commit()
        expired_cards = self.backend["_elenca_richieste_disponibilita_chat"](
            conn.cursor(), 2, 1
        )
        self.assertEqual(expired_cards[0]["stato"], "scaduta")

        for index in range(55):
            created = now - timedelta(minutes=index + 1)
            conn.execute("""
                INSERT INTO richieste_disponibilita (
                    annuncio_id, richiedente_id, offerente_id, a_chiamata,
                    stato, risposta_at, versione, created_at, updated_at
                ) VALUES (10, 1, 2, 0, 'disponibile', ?, 1, ?, ?)
            """, (created, created, created))
        conn.commit()

        cards = self.backend["_elenca_richieste_disponibilita_chat"](
            conn.cursor(), 2, 1
        )
        conn.close()

        self.assertEqual(len(cards), 50)
        self.assertTrue(all(card["inviata_da_me"] is False for card in cards))

    def test_blocco_rende_card_chat_sola_lettura_senza_nasconderla(self):
        dispatch = self.create_request()
        conn = self.connect()
        conn.execute("INSERT INTO chat_blocchi VALUES (2, 1)")
        conn.commit()

        cards = self.backend["_elenca_richieste_disponibilita_chat"](
            conn.cursor(),
            2,
            1,
        )
        conn.close()

        card = next(
            item for item in cards
            if item["id"] == dispatch["richiesta_id"]
        )
        self.assertTrue(card["conversazione_bloccata"])
        self.assertTrue(card["sono_offerente"])
        self.assertFalse(card["posso_rispondere"])
        self.assertFalse(card["inviata_da_me"])

    def test_lock_postgres_qualificati_e_deep_link_login_preservato(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        function_sources = {}
        for function_name in (
            "_prenota_richiesta_disponibilita",
            "_prenota_risposta_disponibilita",
            "chat_conversazione_view",
        ):
            node = next(
                item
                for item in tree.body
                if isinstance(item, ast.FunctionDef)
                and item.name == function_name
            )
            function_sources[function_name] = ast.get_source_segment(
                source,
                node,
            )

        self.assertIn(
            '" FOR UPDATE OF a"',
            function_sources["_prenota_richiesta_disponibilita"],
        )
        self.assertIn(
            '" FOR UPDATE OF rd"',
            function_sources["_prenota_risposta_disponibilita"],
        )
        route_source = function_sources["chat_conversazione_view"]
        self.assertIn('request.full_path', route_source)
        self.assertIn('url_for("login", next=next_url)', route_source)

    def test_route_invia_canali_solo_dopo_commit(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for function_name in (
            "crea_richiesta_disponibilita_route",
            "rispondi_richiesta_disponibilita_route",
        ):
            node = next(
                item
                for item in tree.body
                if isinstance(item, ast.FunctionDef)
                and item.name == function_name
            )
            body = ast.get_source_segment(source, node)
            self.assertLess(
                body.index("_schede_profilo_commit(cur)"),
                body.index("_invia_canali_richiesta_disponibilita("),
            )
        helper = self.backend["_invia_canali_richiesta_disponibilita"]
        calls = []
        self.backend["emit_update_notifications"] = (
            lambda user_id: calls.append(("emit", user_id))
        )
        self.backend["invia_push"] = (
            lambda *args, **kwargs: calls.append(("push", args, kwargs))
        )
        self.backend["_invia_email"] = (
            lambda **kwargs: calls.append(("email", kwargs)) or True
        )
        helper({
            "destinatario_id": 2,
            "destinatario_email": "owner@example.test",
            "email_notifiche": 1,
            "language": "fr",
            "link": "/chat/1?richiesta_disponibilita=1",
            "titolo": "Titolo",
            "messaggio": "Messaggio",
        }, titolo_email="Oggetto", cta_email="Apri",
           messaggio_email_source="Messaggio")
        self.assertEqual([call[0] for call in calls], ["emit", "push", "email"])
        self.assertEqual(calls[-1][1]["language"], "fr")

    def test_bootstrap_sqlite_crea_tabelle_e_indice_additivi(self):
        source = (ROOT / "init_db.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "crea_tabelle_richieste_disponibilita"
        )
        bootstrap_path = Path(self.temp_dir.name) / "bootstrap.sqlite3"

        def connect():
            connection = sqlite3.connect(bootstrap_path)
            connection.execute("PRAGMA foreign_keys = ON")
            return connection

        namespace = {
            "IS_POSTGRES": False,
            "get_conn": connect,
            "sql": lambda query: query,
            "pk_col": lambda: "INTEGER PRIMARY KEY AUTOINCREMENT",
            "dt_col": lambda default=False: (
                "TEXT DEFAULT CURRENT_TIMESTAMP" if default else "TEXT"
            ),
        }
        exec(
            compile(
                ast.Module(body=[function], type_ignores=[]),
                "init_db.py",
                "exec",
            ),
            namespace,
        )
        conn = connect()
        conn.executescript("""
            CREATE TABLE utenti (id INTEGER PRIMARY KEY);
            CREATE TABLE annunci (id INTEGER PRIMARY KEY);
        """)
        conn.commit()
        conn.close()
        namespace["crea_tabelle_richieste_disponibilita"]()

        conn = connect()
        tables = {
            row[0]
            for row in conn.execute("""
                SELECT name FROM sqlite_master
                WHERE type = 'table'
                  AND name LIKE 'richieste_disponibilita%'
            """)
        }
        indexes = {
            row[0]
            for row in conn.execute("""
                SELECT name FROM sqlite_master WHERE type = 'index'
            """)
        }
        request_columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(richieste_disponibilita)"
            )
        }
        conn.close()
        self.assertEqual(tables, {
            "richieste_disponibilita",
            "richieste_disponibilita_fasce",
            "richieste_disponibilita_intervalli",
        })
        self.assertIn("ux_richieste_disponibilita_pendente", indexes)
        self.assertIn("a_chiamata", request_columns)

        init_tree = ast.parse(source)
        init_function = next(
            node
            for node in init_tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "inizializza_database"
        )
        init_source = ast.get_source_segment(source, init_function)
        self.assertIn(
            "crea_tabelle_richieste_disponibilita()",
            init_source,
        )

    def test_eliminazione_account_rimuove_richieste_in_entrambe_le_direzioni(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        route = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "elimina_account_step2"
        )
        route_source = ast.get_source_segment(source, route)
        self.assertIn("richieste_disponibilita_fasce", route_source)
        self.assertIn("richieste_disponibilita_intervalli", route_source)
        self.assertIn("DELETE FROM richieste_disponibilita", route_source)
        self.assertIn("richiedente_id = ?", route_source)
        self.assertIn("offerente_id = ?", route_source)


if __name__ == "__main__":
    unittest.main()
