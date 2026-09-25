import sqlite3
import unittest

from flask import Flask

import models


class ChatThreadsAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test-chat-threads"
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.app.config.update(
            DB_CONN_FACTORY=lambda: self.conn,
            IS_POSTGRES=False,
        )
        self._create_base_schema()
        self._insert_users()

    def tearDown(self):
        self.conn.close()

    def _create_base_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                ruolo TEXT,
                username TEXT NOT NULL,
                nome TEXT,
                cognome TEXT,
                foto_profilo TEXT,
                sospeso INTEGER NOT NULL DEFAULT 0,
                disattivato_admin INTEGER NOT NULL DEFAULT 0,
                attivo INTEGER NOT NULL DEFAULT 1,
                x25519_pub TEXT
            );

            CREATE TABLE messaggi_chat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mittente_id INTEGER NOT NULL,
                destinatario_id INTEGER NOT NULL,
                ciphertext TEXT,
                nonce TEXT,
                eph_pub TEXT,
                eph_priv_enc TEXT,
                eph_priv_nonce TEXT,
                created_at TEXT NOT NULL,
                edited_at TEXT,
                deleted_at TEXT,
                updated_at TEXT,
                consegnato INTEGER NOT NULL DEFAULT 0,
                letto INTEGER NOT NULL DEFAULT 0,
                chat_chiusa INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE chat_chiusure (
                user_id INTEGER NOT NULL,
                admin_id INTEGER NOT NULL,
                closed_at TEXT NOT NULL
            );

            CREATE TABLE chat_blocchi (
                bloccante_id INTEGER NOT NULL,
                bloccato_id INTEGER NOT NULL
            );

            CREATE TABLE chat_unread_email_cycles (
                user_id INTEGER PRIMARY KEY
            );
            """
        )

    def _create_availability_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE richieste_disponibilita (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                annuncio_id INTEGER NOT NULL,
                richiedente_id INTEGER NOT NULL,
                offerente_id INTEGER NOT NULL,
                stato TEXT NOT NULL DEFAULT 'in_attesa',
                risposta_at TEXT,
                evento_letto_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT
            );
            """
        )

    def _insert_users(self):
        self.conn.executemany(
            """
            INSERT INTO utenti (
                id, ruolo, username, nome, cognome, foto_profilo,
                sospeso, disattivato_admin, attivo
            ) VALUES (?, 'user', ?, ?, ?, ?, 0, 0, 1)
            """,
            (
                (1, "OWNER", "Owner", "Uno", "owner.jpg"),
                (2, "REQUESTER", "Requester", "Due", "requester.jpg"),
                (3, "THIRD", "Third", "Tre", "third.jpg"),
            ),
        )
        self.conn.commit()

    def _chat_threads(self, user_id=1):
        with self.app.test_request_context("/chat"):
            return models.chat_threads(user_id)

    def _insert_message(self, sender, recipient, created_at, *, read=1):
        self.conn.execute(
            """
            INSERT INTO messaggi_chat (
                mittente_id, destinatario_id, ciphertext, nonce, eph_pub,
                eph_priv_enc, eph_priv_nonce, created_at, updated_at,
                consegnato, letto, chat_chiusa
            ) VALUES (?, ?, 'cipher', 'nonce', 'pub', 'priv', 'privnonce',
                      ?, ?, 1, ?, 0)
            """,
            (sender, recipient, created_at, created_at, read),
        )
        self.conn.commit()

    def _insert_request(
        self,
        requester,
        offerer,
        created_at,
        *,
        updated_at=None,
        state="in_attesa",
        listing_id=10,
        response_at=None,
        event_read_at=None,
    ):
        self.conn.execute(
            """
            INSERT INTO richieste_disponibilita (
                annuncio_id, richiedente_id, offerente_id, stato,
                risposta_at, evento_letto_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                listing_id,
                requester,
                offerer,
                state,
                response_at,
                event_read_at,
                created_at,
                updated_at or created_at,
            ),
        )
        self.conn.commit()

    def test_request_without_messages_creates_one_thread_per_pair(self):
        self._create_availability_schema()
        self._insert_request(2, 1, "2026-09-25T09:00:00+00:00")

        threads = self._chat_threads(1)

        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["altro_id"], 2)
        self.assertEqual(threads[0]["altro_username"], "REQUESTER")
        self.assertEqual(
            threads[0]["ultimo_testo"],
            "Richiesta di disponibilità",
        )
        self.assertEqual(
            threads[0]["ultimo_evento_tipo"],
            "richiesta_disponibilita",
        )
        self.assertEqual(threads[0]["richiesta_disponibilita_id"], 1)
        self.assertEqual(threads[0]["ultimo_mittente_id"], 2)
        self.assertEqual(threads[0]["non_letti"], 1)

        # Chi ha inviato la richiesta non deve vedere il proprio evento come
        # non letto, anche se lo stato di lettura della card e ancora NULL.
        requester_threads = self._chat_threads(2)
        self.assertEqual(requester_threads[0]["non_letti"], 0)

    def test_opening_chat_marks_inbound_request_card_as_read(self):
        self._create_availability_schema()
        self._insert_request(2, 1, "2026-09-25T09:00:00+00:00")

        self.assertEqual(self._chat_threads(1)[0]["non_letti"], 1)

        with self.app.test_request_context("/chat/2"):
            models.chat_segna_letti(1, 2)

        event = self.conn.execute(
            "SELECT evento_letto_at FROM richieste_disponibilita"
        ).fetchone()
        self.assertIsNotNone(event["evento_letto_at"])
        self.assertEqual(self._chat_threads(1)[0]["non_letti"], 0)

    def test_global_unread_count_includes_inbound_request(self):
        self._create_availability_schema()
        self._insert_request(2, 1, "2026-09-25T09:00:00+00:00")

        with self.app.test_request_context("/chat"):
            self.assertEqual(models.count_chat_non_letti(1), 1)

    def test_request_and_message_unread_counts_are_added(self):
        self._create_availability_schema()
        self._insert_request(2, 1, "2026-09-25T09:00:00+00:00")
        self._insert_message(
            2,
            1,
            "2026-09-25T10:00:00+00:00",
            read=0,
        )

        thread = self._chat_threads(1)[0]
        self.assertEqual(thread["non_letti"], 2)

    def test_message_and_request_merge_and_use_latest_event(self):
        self._create_availability_schema()
        self._insert_message(1, 2, "2026-09-25T08:00:00+00:00")
        self._insert_request(2, 1, "2026-09-25T09:00:00+00:00")

        threads = self._chat_threads(1)

        self.assertEqual(len(threads), 1)
        self.assertEqual(
            threads[0]["ultimo_evento_tipo"],
            "richiesta_disponibilita",
        )
        self.assertEqual(
            threads[0]["ultimo_testo"],
            "Richiesta di disponibilità",
        )

        self._insert_message(2, 1, "2026-09-25T10:00:00+00:00")
        threads = self._chat_threads(1)

        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["ultimo_evento_tipo"], "messaggio")
        self.assertEqual(threads[0]["ultimo_testo"], "🔒 Messaggio cifrato")

    def test_threads_are_sorted_by_latest_message_or_request_event(self):
        self._create_availability_schema()
        self._insert_message(1, 2, "2026-09-25T08:00:00+00:00")
        self._insert_request(3, 1, "2026-09-25T11:00:00+00:00")

        threads = self._chat_threads(1)

        self.assertEqual([row["altro_id"] for row in threads], [3, 2])

    def test_response_update_is_the_request_event_timestamp_and_actor(self):
        self._create_availability_schema()
        self._insert_request(
            2,
            1,
            "2026-09-25T08:00:00+00:00",
            updated_at="2026-09-25T12:00:00+00:00",
            state="disponibile",
            response_at="2026-09-25T12:00:00+00:00",
        )

        threads = self._chat_threads(1)

        self.assertEqual(
            threads[0]["ultimo_invio"],
            "2026-09-25T12:00:00+00:00",
        )
        self.assertEqual(threads[0]["ultimo_mittente_id"], 1)
        self.assertEqual(threads[0]["ultimo_destinatario_id"], 2)
        self.assertEqual(threads[0]["non_letti"], 0)

        requester_threads = self._chat_threads(2)
        self.assertEqual(requester_threads[0]["non_letti"], 1)

    def test_response_event_is_counted_globally_for_requester(self):
        self._create_availability_schema()
        self._insert_request(
            2,
            1,
            "2026-09-25T08:00:00+00:00",
            updated_at="2026-09-25T12:00:00+00:00",
            state="informazioni",
            response_at="2026-09-25T12:00:00+00:00",
        )

        with self.app.test_request_context("/chat"):
            self.assertEqual(models.count_chat_non_letti(2), 1)

    def test_missing_availability_table_preserves_existing_chat_list(self):
        self._insert_message(2, 1, "2026-09-25T10:00:00+00:00", read=0)

        threads = self._chat_threads(1)

        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["altro_id"], 2)
        self.assertEqual(threads[0]["ultimo_evento_tipo"], "messaggio")
        self.assertEqual(threads[0]["non_letti"], 1)

    def test_missing_availability_table_preserves_global_unread_count(self):
        self._insert_message(2, 1, "2026-09-25T10:00:00+00:00", read=0)

        with self.app.test_request_context("/chat"):
            self.assertEqual(models.count_chat_non_letti(1), 1)


if __name__ == "__main__":
    unittest.main()
