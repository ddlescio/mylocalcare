import sqlite3
import unittest

from models import _chat_verifica_partecipanti_abilitati_cursor


SCHEMA_UTENTI = """
    CREATE TABLE utenti (
        id INTEGER PRIMARY KEY,
        attivo INTEGER NOT NULL DEFAULT 1,
        sospeso INTEGER NOT NULL DEFAULT 0,
        disattivato_admin INTEGER NOT NULL DEFAULT 0,
        eliminato INTEGER NOT NULL DEFAULT 0
    )
"""


class DisattivazioneAccountTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(SCHEMA_UTENTI)
        self.conn.executemany(
            "INSERT INTO utenti (id) VALUES (?)",
            [(1,), (2,)],
        )

    def tearDown(self):
        self.conn.close()

    def test_chat_consentita_tra_account_abilitati(self):
        _chat_verifica_partecipanti_abilitati_cursor(
            self.conn.cursor(),
            1,
            2,
        )

    def test_account_disattivato_non_puo_inviare(self):
        self.conn.execute(
            "UPDATE utenti SET attivo = 0, disattivato_admin = 1 WHERE id = 1"
        )

        with self.assertRaisesRegex(
            PermissionError,
            "mittente non abilitato",
        ):
            _chat_verifica_partecipanti_abilitati_cursor(
                self.conn.cursor(),
                1,
                2,
            )

    def test_account_disattivato_non_puo_ricevere(self):
        self.conn.execute(
            "UPDATE utenti SET attivo = 0, disattivato_admin = 1 WHERE id = 2"
        )

        with self.assertRaisesRegex(
            PermissionError,
            "destinatario non disponibile",
        ):
            _chat_verifica_partecipanti_abilitati_cursor(
                self.conn.cursor(),
                1,
                2,
            )


if __name__ == "__main__":
    unittest.main()
