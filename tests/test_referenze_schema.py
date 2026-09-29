import ast
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_reference_bootstrap(connect):
    source = (ROOT / "init_db.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "crea_tabelle_referenze"
    )
    namespace = {
        "IS_POSTGRES": False,
        "get_conn": connect,
        "sql": lambda query: query,
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
    return namespace["crea_tabelle_referenze"]


class ReferenceSchemaTest(unittest.TestCase):
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
        self.bootstrap = load_reference_bootstrap(connect)
        conn = self.connect()
        conn.executescript("""
            CREATE TABLE utenti (id INTEGER PRIMARY KEY);
            INSERT INTO utenti (id) VALUES (1), (2);
        """)
        conn.commit()
        conn.close()

    def tearDown(self):
        self.database_path.unlink(missing_ok=True)

    def test_bootstrap_sqlite_idempotente_e_completo(self):
        self.bootstrap()
        self.bootstrap()
        conn = self.connect()
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        reference_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(referenze)")
        }
        contact_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(referenze_contatti)")
        }
        outbox_columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(referenze_notifiche_outbox)"
            )
        }
        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        conn.close()

        self.assertTrue(
            {
                "referenze", "referenze_contatti", "referenze_eventi",
                "referenze_notifiche_outbox",
            }
            .issubset(tables)
        )
        self.assertTrue(
            {
                "stato_risposta", "stato_verifica", "metodo_verifica",
                "nota_admin", "autorizza_pubblicazione",
                "autorizza_testo_pubblico", "consenso_trattamento_at",
                "autorizza_contatto_verifica", "autorizzazione_contatto_at",
                "pubblicazione_approvata_admin",
                "pubblicazione_approvata_at",
                "pubblicazione_approvata_da_admin_id",
                "visibile_profilo",
            }.issubset(reference_columns)
        )
        self.assertTrue(
            {
                "email_cifrata", "email_nonce", "email_tag", "email_hash",
                "nome_cifrato", "nome_nonce", "nome_tag",
                "telefono_cifrato", "telefono_nonce", "telefono_tag",
                "messaggio_invito_cifrato", "token_hash",
                "contatto_purge_at", "contatto_purged_at",
            }.issubset(contact_columns)
        )
        self.assertTrue({
            "event_key", "referenza_id", "destinatario_id",
            "destinatario_tipo", "titolo", "messaggio", "link",
            "push_richiesta", "notifica_creata_at", "tentativi",
            "disponibile_at", "bloccata_at", "blocco_token",
            "elaborata_at", "ultimo_errore",
        }.issubset(outbox_columns))
        self.assertIn("idx_referenze_coda_admin", indexes)
        self.assertIn("idx_referenze_eventi_storico", indexes)
        self.assertIn("idx_referenze_outbox_pending", indexes)
        self.assertIn("idx_referenze_outbox_destinatario", indexes)

    def test_bootstrap_aggiunge_retention_a_tabella_contatti_precedente(self):
        conn = self.connect()
        conn.executescript("""
            CREATE TABLE referenze_contatti (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referenza_id INTEGER NOT NULL UNIQUE,
                email_cifrata TEXT,
                email_nonce TEXT,
                email_tag TEXT,
                email_key_id TEXT,
                email_hash TEXT,
                nome_cifrato TEXT,
                nome_nonce TEXT,
                nome_tag TEXT,
                messaggio_invito_cifrato TEXT,
                messaggio_invito_nonce TEXT,
                messaggio_invito_tag TEXT,
                token_hash TEXT UNIQUE,
                token_expires_at TEXT,
                token_consumed_at TEXT,
                ultimo_invio_at TEXT,
                numero_invii INTEGER NOT NULL DEFAULT 0,
                aperto_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        conn.close()

        self.bootstrap()

        conn = self.connect()
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(referenze_contatti)")
        }
        conn.close()
        self.assertTrue({
            "ultimo_errore_invio",
            "contatto_purge_at",
            "contatto_purged_at",
            "telefono_cifrato",
            "telefono_nonce",
            "telefono_tag",
        }.issubset(columns))

    def test_bootstrap_ripara_schema_legacy_e_permette_transizione_post(self):
        conn = self.connect()
        conn.executescript("""
            CREATE TABLE referenze (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                tipo_rapporto TEXT NOT NULL
            );
            CREATE TABLE referenze_contatti (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referenza_id INTEGER NOT NULL
            );
            CREATE TABLE referenze_eventi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referenza_id INTEGER NOT NULL,
                tipo_evento TEXT NOT NULL,
                attore_tipo TEXT NOT NULL
            );
        """)
        conn.commit()
        conn.close()

        self.bootstrap()
        self.bootstrap()

        conn = self.connect()
        reference_id = conn.execute("""
            INSERT INTO referenze (
                utente_id, categoria_slug, tipo_rapporto,
                stato_risposta, stato_verifica, versione,
                created_at, updated_at
            ) VALUES (
                1, 'babysitter', 'famiglia', 'in_attesa',
                'non_esaminata', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """).lastrowid
        conn.execute("""
            INSERT INTO referenze_contatti (
                referenza_id, token_hash, token_expires_at,
                telefono_cifrato, telefono_nonce, telefono_tag,
                created_at, updated_at
            ) VALUES (
                ?, 'token-hash', '2099-01-01T00:00:00+00:00',
                NULL, NULL, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """, (reference_id,))

        updated = conn.execute("""
            UPDATE referenze
            SET esperienza_diretta = 1,
                stato_risposta = 'risposta_ricevuta',
                stato_verifica = 'in_coda',
                autorizza_contatto_verifica = 1,
                consenso_versione = 'references_2026_v2',
                consenso_trattamento_at = CURRENT_TIMESTAMP,
                autorizzazione_contatto_at = CURRENT_TIMESTAMP,
                risposta_at = CURRENT_TIMESTAMP,
                versione = versione + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND stato_risposta = 'in_attesa'
              AND EXISTS (
                  SELECT 1 FROM referenze_contatti c
                  WHERE c.referenza_id = referenze.id
                    AND c.token_hash = 'token-hash'
                    AND c.token_consumed_at IS NULL
                    AND datetime(c.token_expires_at) > CURRENT_TIMESTAMP
              )
        """, (reference_id,))
        self.assertEqual(updated.rowcount, 1)
        conn.execute("""
            UPDATE referenze_contatti
            SET token_consumed_at = CURRENT_TIMESTAMP,
                telefono_cifrato = 'cipher',
                telefono_nonce = 'nonce',
                telefono_tag = 'tag',
                contatto_purge_at = '2099-04-01T00:00:00+00:00',
                updated_at = CURRENT_TIMESTAMP
            WHERE referenza_id = ? AND token_consumed_at IS NULL
        """, (reference_id,))
        conn.execute("""
            INSERT INTO referenze_eventi (
                referenza_id, tipo_evento, attore_tipo,
                dettagli_snapshot, created_at
            ) VALUES (
                ?, 'risposta_ricevuta', 'referente', '{}', CURRENT_TIMESTAMP
            )
        """, (reference_id,))
        conn.commit()

        reference = conn.execute(
            "SELECT * FROM referenze WHERE id = ?", (reference_id,)
        ).fetchone()
        contact = conn.execute(
            "SELECT * FROM referenze_contatti WHERE referenza_id = ?",
            (reference_id,),
        ).fetchone()
        event = conn.execute(
            "SELECT * FROM referenze_eventi WHERE referenza_id = ?",
            (reference_id,),
        ).fetchone()
        conn.close()

        self.assertEqual(reference["stato_risposta"], "risposta_ricevuta")
        self.assertEqual(reference["stato_verifica"], "in_coda")
        self.assertEqual(reference["consenso_versione"], "references_2026_v2")
        self.assertEqual(contact["telefono_cifrato"], "cipher")
        self.assertIsNotNone(contact["token_consumed_at"])
        self.assertEqual(event["attore_tipo"], "referente")
        self.assertIsNotNone(event["created_at"])

    def test_vincoli_privacy_stati_e_cascade(self):
        self.bootstrap()
        conn = self.connect()
        cursor = conn.execute("""
            INSERT INTO referenze (
                utente_id, categoria_slug, tipo_rapporto,
                stato_risposta, stato_verifica, created_at, updated_at
            ) VALUES (
                1, 'babysitter', 'famiglia',
                'in_attesa', 'non_esaminata',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
        """)
        reference_id = cursor.lastrowid
        conn.execute("""
            INSERT INTO referenze_contatti (
                referenza_id,
                email_cifrata, email_nonce, email_tag,
                email_key_id, email_hash,
                nome_cifrato, nome_nonce, nome_tag,
                token_hash, token_expires_at,
                created_at, updated_at
            ) VALUES (?, 'cipher', 'nonce', 'tag', 'v1', 'hash',
                      'name-cipher', 'name-nonce', 'name-tag',
                      'token-hash', '2026-10-12',
                      CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (reference_id,))
        conn.execute("""
            INSERT INTO referenze_eventi (
                referenza_id, tipo_evento, attore_tipo, attore_utente_id
            ) VALUES (?, 'creata', 'utente', 1)
        """, (reference_id,))
        conn.commit()

        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("""
                INSERT INTO referenze (
                    utente_id, categoria_slug, tipo_rapporto,
                    stato_risposta, autorizza_pubblicazione,
                    created_at, updated_at
                ) VALUES (
                    2, 'caregiver', 'cliente',
                    'in_attesa', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                )
            """)
        conn.rollback()

        conn.execute("DELETE FROM utenti WHERE id = 1")
        conn.commit()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM referenze").fetchone()[0], 0)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM referenze_contatti").fetchone()[0],
            0,
        )
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM referenze_eventi").fetchone()[0],
            0,
        )
        conn.close()

    def test_migrazione_postgres_ha_grant_e_nessun_contatto_in_chiaro(self):
        migration = (
            ROOT / "migrations" / "20260928_referenze.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE IF NOT EXISTS referenze", migration)
        self.assertIn("CREATE TABLE IF NOT EXISTS referenze_contatti", migration)
        self.assertIn("CREATE TABLE IF NOT EXISTS referenze_eventi", migration)
        self.assertIn("email_cifrata TEXT", migration)
        self.assertIn("nome_cifrato TEXT", migration)
        self.assertIn("telefono_cifrato TEXT", migration)
        self.assertNotIn("referente_telefono TEXT", migration)
        self.assertIn("messaggio_invito_cifrato TEXT", migration)
        self.assertIn("token_hash TEXT UNIQUE", migration)
        self.assertIn("metodo_verifica", migration)
        self.assertIn("nota_admin", migration)
        self.assertIn("autorizza_contatto_verifica", migration)
        self.assertIn("pubblicazione_approvata_admin", migration)
        self.assertIn("pubblicazione_approvata_at", migration)
        self.assertIn("pubblicazione_approvata_da_admin_id", migration)
        self.assertIn("visibile_profilo", migration)
        self.assertIn(
            "ADD COLUMN IF NOT EXISTS contatto_purge_at",
            migration,
        )
        self.assertIn(
            "ADD COLUMN IF NOT EXISTS contatto_purged_at",
            migration,
        )
        self.assertNotIn("referente_email TEXT", migration)
        self.assertIn("TO localcare_app", migration)
        self.assertIn("referenze_eventi_id_seq", migration)

        repair = (
            ROOT / "migrations" / "20260928_referenze_riparazione.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("ADD COLUMN IF NOT EXISTS risposta_at", repair)
        self.assertIn("ADD COLUMN IF NOT EXISTS telefono_cifrato", repair)
        self.assertIn("referenze_contatti_telefono_check_v2", repair)
        self.assertIn("referenze_eventi_attore_tipo_check_v2", repair)
        self.assertIn("CREATE UNIQUE INDEX IF NOT EXISTS", repair)
        self.assertNotIn("referente_telefono TEXT", repair)
        self.assertNotRegex(repair, r"LOOP\s*\n\s*LOOP")
        self.assertEqual(
            len(re.findall(r"^\s*LOOP\s*$", repair, re.MULTILINE)),
            len(re.findall(r"^\s*END LOOP;\s*$", repair, re.MULTILINE)),
        )

        outbox = (
            ROOT / "migrations" /
            "20260929_referenze_notifiche_outbox.sql"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS referenze_notifiche_outbox",
            outbox,
        )
        self.assertIn("event_key TEXT NOT NULL UNIQUE", outbox)
        self.assertIn("idx_referenze_outbox_pending", outbox)
        self.assertIn("ON DELETE CASCADE", outbox)
        self.assertIn("ON TABLE referenze_notifiche_outbox", outbox)
        self.assertIn("referenze_notifiche_outbox_id_seq", outbox)

    def test_bootstrap_completo_invoca_referenze(self):
        source = (ROOT / "init_db.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        initializer = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "inizializza_database"
        )
        calls = {
            node.func.id
            for node in ast.walk(initializer)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn("crea_tabelle_referenze", calls)


if __name__ == "__main__":
    unittest.main()
