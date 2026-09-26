import unittest
from pathlib import Path

from flask import Flask, request, session

from chat_realtime import register_chat_socket_handlers


ROOT = Path(__file__).resolve().parents[1]
CHAT_TEMPLATE = (
    ROOT / "templates" / "chat_conversazione.html"
).read_text(encoding="utf-8")
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")


class FakeSocket:
    def __init__(self):
        self.handlers = {}

    def on(self, event):
        def decorator(handler):
            self.handlers[event] = handler
            return handler

        return decorator

    def emit(self, *args, **kwargs):
        return None

    def start_background_task(self, target, *args):
        return None

    def sleep(self, delay):
        return None


class FakeCursor:
    def __init__(self, users):
        self.users = users
        self.closed = False

    def execute(self, query, params=()):
        return self

    def fetchall(self):
        return self.users

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, users):
        self.cursor = FakeCursor(users)
        self.closed = False

    def execute(self, query, params=()):
        return self

    def commit(self):
        return None

    def close(self):
        self.closed = True


class ChatProfilePhotoGuardTest(unittest.TestCase):
    def make_handler(self, photo_value):
        flask_app = Flask(__name__)
        flask_app.secret_key = "test-secret"
        flask_app.config["CHAT_RECENTLY_READ_TTL"] = 0
        socket = FakeSocket()
        sent_messages = []
        connection = FakeConnection([
            {
                "id": 1,
                "ruolo": "user",
                "foto_profilo": photo_value,
                "attivo": 1,
                "sospeso": 0,
                "disattivato_admin": 0,
                "eliminato": 0,
            },
            {
                "id": 2,
                "ruolo": "user",
                "foto_profilo": "recipient.jpg",
                "attivo": 1,
                "sospeso": 0,
                "disattivato_admin": 0,
                "eliminato": 0,
            },
        ])

        register_chat_socket_handlers(
            socket,
            flask_app,
            get_db_connection=lambda: connection,
            get_cursor=lambda conn: conn.cursor,
            sql=lambda query: query,
            chat_invia=lambda *args: sent_messages.append(args) or 99,
            chat_stato_blocco=lambda *args: {
                "bloccata": False,
                "bloccato_da_me": False,
                "sono_stato_bloccato": False,
            },
            chat_segna_letti=lambda *args: None,
            emit_to_user_sids=lambda *args, **kwargs: None,
            chat_count_unread=lambda user_id: 0,
            set_open_chat=lambda *args: None,
            get_open_chat=lambda user_id: None,
            clear_open_chat=lambda *args: None,
            invia_push=lambda *args, **kwargs: None,
            recently_read_timers={},
            account_is_enabled=lambda user_id: True,
        )
        return flask_app, socket.handlers["send_message"], sent_messages

    def test_realtime_send_after_photo_removal_returns_dashboard_action(self):
        for photo_value in (None, "", "   "):
            with self.subTest(photo_value=photo_value):
                flask_app, handler, sent_messages = self.make_handler(
                    photo_value
                )

                with flask_app.test_request_context("/"):
                    session["utente_id"] = 1
                    request.sid = "socket-test"
                    response = handler({
                        "destinatario_id": 2,
                        "testo": "Ciao",
                    })

                self.assertFalse(response["ok"])
                self.assertEqual(response["code"], "foto_profilo_richiesta")
                self.assertEqual(response["action_url"], "/utente/dashboard")
                self.assertIn("foto profilo", response["error"])
                self.assertEqual(sent_messages, [])

    def test_chat_client_handles_socket_and_http_photo_errors(self):
        self.assertIn("function handleProfilePhotoRequired(payload)", CHAT_TEMPLATE)
        self.assertIn("handleProfilePhotoRequired(response)", CHAT_TEMPLATE)
        self.assertGreaterEqual(
            CHAT_TEMPLATE.count("handleProfilePhotoRequired(data)"),
            2,
        )
        self.assertIn("handleProfilePhotoRequired(msgs)", CHAT_TEMPLATE)
        self.assertIn("payload.action_url || '/utente/dashboard'", CHAT_TEMPLATE)
        self.assertIn("window.alert(", CHAT_TEMPLATE)

    def test_http_guards_return_the_dashboard_action(self):
        self.assertIn('"code": "foto_profilo_richiesta"', APP_SOURCE)
        self.assertIn('"action_url": url_for("dashboard")', APP_SOURCE)
        self.assertIn(
            "return _chat_foto_profilo_json_error()",
            APP_SOURCE,
        )
        self.assertIn(
            'code="foto_profilo_richiesta"',
            APP_SOURCE,
        )


if __name__ == "__main__":
    unittest.main()
