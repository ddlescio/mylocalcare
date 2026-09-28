import ast
from datetime import datetime, timezone
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_function(path, function_name, namespace):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"),
        namespace,
    )
    return namespace[function_name]


class _FakeApp:
    config = {"IS_POSTGRES": False}


class ReferenceRetentionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        self.database_path = Path(temporary.name)

        def connect():
            connection = sqlite3.connect(self.database_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            return connection

        self.connect = connect
        bootstrap = _load_function(
            ROOT / "init_db.py",
            "crea_tabelle_referenze",
            {
                "IS_POSTGRES": False,
                "get_conn": connect,
                "sql": lambda query: query,
                "dt_col": lambda default=False: (
                    "TEXT DEFAULT CURRENT_TIMESTAMP" if default else "TEXT"
                ),
            },
        )
        conn = connect()
        conn.execute("CREATE TABLE utenti (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO utenti (id) VALUES (1)")
        conn.commit()
        conn.close()
        bootstrap()

        self.cleanup = _load_function(
            ROOT / "app.py",
            "pulisci_referenze_scadute_e_contatti",
            {
                "app": _FakeApp(),
                "get_db_connection": connect,
                "get_cursor": lambda connection: connection.cursor(),
                "sql": lambda query: query,
                "json": json,
                "log_exception_safe": lambda *args, **kwargs: None,
            },
        )
        parse_datetime = _load_function(
            ROOT / "app.py",
            "_referenze_datetime",
            {"datetime": datetime, "timezone": timezone},
        )
        self.private_state = _load_function(
            ROOT / "app.py",
            "_referenza_private_state",
            {
                "datetime": datetime,
                "timezone": timezone,
                "_referenze_datetime": parse_datetime,
            },
        )

    def tearDown(self):
        self.database_path.unlink(missing_ok=True)

    def test_scade_invito_e_rimuove_tutti_i_dati_privati_insieme(self):
        conn = self.connect()
        reference_id = conn.execute("""
            INSERT INTO referenze (
                utente_id, categoria_slug, tipo_rapporto,
                stato_risposta, stato_verifica, created_at, updated_at
            ) VALUES (
                1, 'babysitter', 'famiglia', 'in_attesa',
                'non_esaminata', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """).lastrowid
        conn.execute("""
            INSERT INTO referenze_contatti (
                referenza_id,
                email_cifrata, email_nonce, email_tag, email_key_id, email_hash,
                nome_cifrato, nome_nonce, nome_tag,
                telefono_cifrato, telefono_nonce, telefono_tag,
                messaggio_invito_cifrato, messaggio_invito_nonce,
                messaggio_invito_tag,
                token_hash, token_expires_at, contatto_purge_at,
                created_at, updated_at
            ) VALUES (
                ?, 'email', 'nonce', 'tag', 'key', 'hash',
                'nome', 'nonce', 'tag',
                'telefono', 'nonce', 'tag',
                'messaggio', 'nonce', 'tag',
                'token', '2020-01-01T00:00:00+00:00',
                '2020-02-01T00:00:00+00:00',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """, (reference_id,))
        conn.commit()
        conn.close()

        result = self.cleanup()
        self.assertEqual(result, {"scadute": 1, "contatti_rimossi": 1})

        conn = self.connect()
        reference = conn.execute(
            "SELECT stato_risposta FROM referenze WHERE id = ?",
            (reference_id,),
        ).fetchone()
        contact = conn.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = ?",
            (reference_id,),
        ).fetchone()
        events = conn.execute(
            "SELECT tipo_evento FROM referenze_eventi WHERE referenza_id = ?",
            (reference_id,),
        ).fetchall()
        conn.close()

        self.assertEqual(reference["stato_risposta"], "scaduta")
        for field in (
            "email_cifrata", "email_nonce", "email_tag", "email_key_id",
            "email_hash", "nome_cifrato", "nome_nonce", "nome_tag",
            "telefono_cifrato", "telefono_nonce", "telefono_tag",
            "messaggio_invito_cifrato", "messaggio_invito_nonce",
            "messaggio_invito_tag", "token_hash", "token_expires_at",
        ):
            self.assertIsNone(contact[field], field)
        self.assertIsNotNone(contact["contatto_purged_at"])
        self.assertEqual(
            [event["tipo_evento"] for event in events],
            ["contatti_rimossi_retention"],
        )

    def test_chiude_la_coda_se_il_recapito_scade_prima_del_controllo(self):
        conn = self.connect()
        reference_id = conn.execute("""
            INSERT INTO referenze (
                utente_id, categoria_slug, tipo_rapporto,
                esperienza_diretta, stato_risposta, stato_verifica,
                autorizza_pubblicazione, consenso_trattamento_at,
                autorizzazione_pubblica_at, risposta_at,
                created_at, updated_at
            ) VALUES (
                1, 'caregiver', 'cliente', 1,
                'risposta_ricevuta', 'in_coda', 1,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """).lastrowid
        conn.execute("""
            INSERT INTO referenze_contatti (
                referenza_id,
                email_cifrata, email_nonce, email_tag, email_key_id, email_hash,
                nome_cifrato, nome_nonce, nome_tag,
                contatto_purge_at, created_at, updated_at
            ) VALUES (
                ?, 'email', 'nonce', 'tag', 'key', 'hash',
                'nome', 'nonce', 'tag',
                '2020-02-01T00:00:00+00:00',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """, (reference_id,))
        conn.commit()
        conn.close()

        result = self.cleanup()
        self.assertEqual(result["contatti_rimossi"], 1)

        conn = self.connect()
        reference = conn.execute("""
            SELECT stato_verifica, metodo_verifica, nota_admin
            FROM referenze
            WHERE id = ?
        """, (reference_id,)).fetchone()
        conn.close()

        self.assertEqual(reference["stato_verifica"], "non_verificabile")
        self.assertEqual(reference["metodo_verifica"], "nessuno")
        self.assertIn("periodo di conservazione", reference["nota_admin"])

    def test_rimozione_recapiti_non_nasconde_esito_finale(self):
        base = {
            "stato_risposta": "risposta_ricevuta",
            "contatto_purged_at": "2026-12-01T00:00:00+00:00",
        }
        self.assertEqual(
            self.private_state({**base, "stato_verifica": "verificata"}),
            "verificata",
        )
        self.assertEqual(
            self.private_state({
                **base,
                "stato_verifica": "non_verificabile",
            }),
            "non_verificabile",
        )

    def test_fallimento_email_non_viene_presentato_come_invito_inviato(self):
        self.assertEqual(
            self.private_state({
                "stato_risposta": "in_attesa",
                "stato_verifica": "non_esaminata",
                "token_expires_at": "2099-01-01T00:00:00+00:00",
                "ultimo_errore_invio": "Invio email non riuscito",
            }),
            "errore_invio",
        )


if __name__ == "__main__":
    unittest.main()
