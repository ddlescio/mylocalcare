import ast
from pathlib import Path
import sqlite3
import unittest

from reference_cleanup import purge_user_reference_data


ROOT = Path(__file__).resolve().parents[1]


def _function_source(path: Path, function_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    return ast.get_source_segment(source, function)


class ReferenceAccountCleanupTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        # Simula anche una installazione legacy senza cascade attive: la
        # pulizia deve essere completa per proprio conto.
        self.conn.execute("PRAGMA foreign_keys = OFF")
        self.conn.executescript("""
            CREATE TABLE referenze (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                testo_referente TEXT,
                consenso_versione TEXT,
                autorizza_pubblicazione INTEGER
            );
            CREATE TABLE referenze_contatti (
                id INTEGER PRIMARY KEY,
                referenza_id INTEGER NOT NULL,
                email_cifrata TEXT,
                token_hash TEXT,
                messaggio_invito_cifrato TEXT
            );
            CREATE TABLE referenze_eventi (
                id INTEGER PRIMARY KEY,
                referenza_id INTEGER NOT NULL,
                tipo_evento TEXT,
                dettagli_snapshot TEXT
            );
            CREATE TABLE referenze_notifiche_outbox (
                id INTEGER PRIMARY KEY,
                referenza_id INTEGER NOT NULL,
                destinatario_id INTEGER NOT NULL,
                messaggio TEXT
            );
        """)
        self.conn.executemany(
            """
                INSERT INTO referenze (
                    id, utente_id, testo_referente, consenso_versione,
                    autorizza_pubblicazione
                ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                (10, 7, "Testo privato", "references_2026_v3", 1),
                (11, 7, "Secondo testo", "references_2026_v3", 0),
                (20, 8, "Da conservare", "references_2026_v3", 1),
            ),
        )
        self.conn.executemany(
            """
                INSERT INTO referenze_contatti (
                    id, referenza_id, email_cifrata, token_hash,
                    messaggio_invito_cifrato
                ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                (100, 10, "email-10", "token-10", "invito-10"),
                (101, 11, "email-11", "token-11", "invito-11"),
                (200, 20, "email-20", "token-20", "invito-20"),
            ),
        )
        self.conn.executemany(
            """
                INSERT INTO referenze_eventi (
                    id, referenza_id, tipo_evento, dettagli_snapshot
                ) VALUES (?, ?, ?, ?)
            """,
            (
                (1000, 10, "consenso_registrato", "consenso-10"),
                (1001, 11, "invito_inviato", "audit-11"),
                (2000, 20, "invito_inviato", "audit-20"),
            ),
        )
        self.conn.executemany(
            """
                INSERT INTO referenze_notifiche_outbox (
                    id, referenza_id, destinatario_id, messaggio
                ) VALUES (?, ?, ?, ?)
            """,
            (
                (500, 10, 7, "owner 10"),
                (501, 11, 2, "admin 11"),
                (502, 20, 7, "owner destinatario da eliminare"),
                (503, 20, 8, "da conservare"),
            ),
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _ids(self, table):
        return [
            row["id"]
            for row in self.conn.execute(f"SELECT id FROM {table} ORDER BY id")
        ]

    def test_purges_parent_sensitive_children_and_audit_without_fk_cascade(self):
        deleted = purge_user_reference_data(
            self.conn.cursor(),
            7,
            postgres=False,
        )

        self.assertEqual(deleted, {
            "referenze_notifiche_outbox": 3,
            "referenze_eventi": 2,
            "referenze_contatti": 2,
            "referenze": 2,
        })
        self.assertEqual(self._ids("referenze"), [20])
        self.assertEqual(self._ids("referenze_contatti"), [200])
        self.assertEqual(self._ids("referenze_eventi"), [2000])
        self.assertEqual(self._ids("referenze_notifiche_outbox"), [503])

    def test_does_not_commit_outside_the_account_deletion_transaction(self):
        purge_user_reference_data(
            self.conn.cursor(),
            7,
            postgres=False,
        )
        self.conn.rollback()

        self.assertEqual(self._ids("referenze"), [10, 11, 20])
        self.assertEqual(self._ids("referenze_contatti"), [100, 101, 200])
        self.assertEqual(self._ids("referenze_eventi"), [1000, 1001, 2000])
        self.assertEqual(
            self._ids("referenze_notifiche_outbox"),
            [500, 501, 502, 503],
        )

    def test_propagates_errors_so_account_deletion_can_rollback_atomically(self):
        self.conn.executescript("""
            CREATE TRIGGER blocca_pulizia_contatti
            BEFORE DELETE ON referenze_contatti
            BEGIN
                SELECT RAISE(ABORT, 'pulizia contatti fallita');
            END;
        """)
        self.conn.commit()

        with self.assertRaises(sqlite3.DatabaseError):
            purge_user_reference_data(
                self.conn.cursor(),
                7,
                postgres=False,
            )
        self.conn.rollback()

        # Gli eventi erano il primo passo: il rollback li ripristina e non
        # viene lasciata una cancellazione account incompleta.
        self.assertEqual(self._ids("referenze"), [10, 11, 20])
        self.assertEqual(self._ids("referenze_contatti"), [100, 101, 200])
        self.assertEqual(self._ids("referenze_eventi"), [1000, 1001, 2000])
        self.assertEqual(
            self._ids("referenze_notifiche_outbox"),
            [500, 501, 502, 503],
        )


class ReferenceAccountCleanupRolloutTest(unittest.TestCase):
    def test_partial_rollout_with_only_parent_table_still_purges_references(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE referenze (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                testo_referente TEXT
            );
            INSERT INTO referenze VALUES (1, 7, 'da eliminare');
            INSERT INTO referenze VALUES (2, 8, 'da conservare');
        """)

        deleted = purge_user_reference_data(
            conn.cursor(),
            7,
            postgres=False,
        )

        self.assertEqual(deleted["referenze"], 1)
        self.assertEqual(
            conn.execute("SELECT id FROM referenze").fetchone()["id"],
            2,
        )
        conn.close()

    def test_schema_not_yet_installed_is_a_safe_noop(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        deleted = purge_user_reference_data(
            conn.cursor(),
            7,
            postgres=False,
        )
        self.assertEqual(deleted, {
            "referenze_eventi": 0,
            "referenze_contatti": 0,
            "referenze": 0,
        })
        conn.close()


class ReferenceAccountCleanupIntegrationTest(unittest.TestCase):
    def test_self_service_and_admin_deletion_use_the_same_cleanup_helper(self):
        self_service = _function_source(
            ROOT / "app.py",
            "elimina_account_step2",
        )
        admin_service = _function_source(
            ROOT / "models.py",
            "elimina_utente",
        )

        self.assertIn("purge_user_reference_data(", self_service)
        self.assertIn("purge_user_reference_data(", admin_service)
        for account_flow in (self_service, admin_service):
            cleanup_position = account_flow.index(
                "purge_user_reference_data("
            )
            anonymization_position = account_flow.index("UPDATE utenti")
            commit_position = account_flow.rindex("conn.commit()")
            self.assertLess(cleanup_position, anonymization_position)
            self.assertLess(cleanup_position, commit_position)
            self.assertIn("conn.rollback()", account_flow)

    def test_reference_migration_has_cascades_as_second_safety_layer(self):
        migration = (
            ROOT / "migrations" / "20260928_referenze.sql"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "REFERENCES utenti(id) ON DELETE CASCADE",
            migration,
        )
        self.assertGreaterEqual(
            migration.count("REFERENCES referenze(id) ON DELETE CASCADE"),
            2,
        )


if __name__ == "__main__":
    unittest.main()
