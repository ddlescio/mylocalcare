import ast
import copy
import html as html_module
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from flask import Flask, g, has_app_context

from i18n import (
    SUPPORTED_LANGUAGES,
    localize_html_document,
    normalize_language,
    translate_source,
)


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "app.py"
APP_SOURCE = APP_PATH.read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)


def _load_functions(names, namespace):
    selected = [
        copy.deepcopy(node)
        for node in APP_TREE.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    exec(
        compile(
            ast.Module(body=selected, type_ignores=[]),
            str(APP_PATH),
            "exec",
        ),
        namespace,
    )
    return namespace


def _function_node(name):
    return next(
        node
        for node in APP_TREE.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


class _PostmarkResponse:
    status_code = 200
    text = ""

    @staticmethod
    def json():
        return {"MessageID": "postmark-test-id", "ErrorCode": 0}


class _PostmarkTransport:
    class exceptions:
        Timeout = TimeoutError

    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _PostmarkResponse()


class TransactionalEmailLanguageTest(unittest.TestCase):
    FUNCTIONS = {
        "_email_privacy_url",
        "_email_footer_text",
        "_email_footer_html",
        "_testo_email_in_html",
        "_costruisci_html_email",
        "_aggiungi_footer_text_se_manca",
        "_aggiungi_footer_html_se_manca",
        "_risolvi_lingua_email",
        "_invia_email",
        "_copy_email_conferma_account",
        "_copy_email_reset_password",
        "invia_email_promemoria_chat",
        "_invia_canali_richiesta_disponibilita",
        "_copy_promemoria_disponibilita",
        "_copy_evento_ciclo_disponibilita",
    }

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "email-language.sqlite3"
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                email TEXT,
                nome TEXT,
                username TEXT,
                lingua_interfaccia TEXT,
                email_notifiche INTEGER DEFAULT 1,
                attivo INTEGER DEFAULT 1,
                sospeso INTEGER DEFAULT 0,
                disattivato_admin INTEGER DEFAULT 0,
                eliminato INTEGER DEFAULT 0
            );
        """)
        conn.executemany("""
            INSERT INTO utenti (
                id, email, nome, username, lingua_interfaccia,
                email_notifiche, attivo, sospeso, disattivato_admin,
                eliminato
            ) VALUES (?, ?, ?, ?, ?, 1, 1, 0, 0, 0)
        """, [
            (1, "fr@example.test", "NomInvariant_X9", "fr-user", "fr"),
            (2, "uk@example.test", "ImyaInvariant_X9", "uk-user", "uk"),
            (3, "invalid@example.test", "Nome", "invalid-user", "xx"),
        ])
        conn.commit()
        conn.close()

        self.app = Flask("email-i18n-payload-test")
        self.app.config.update(
            APP_BASE_URL="https://www.mylocalcare.it",
            TESTING=True,
        )
        self.transport = _PostmarkTransport()
        self.logs = []
        namespace = {
            "app": self.app,
            "g": g,
            "os": os,
            "requests": self.transport,
            "MAIL_FROM_ADDRESS": "info@mylocalcare.it",
            "MAIL_FROM_NAME": "MyLocalCare",
            "EMAIL_FOOTER_BRAND": "MyLocalCare",
            "EMAIL_FOOTER_CONTACT": "info@mylocalcare.it",
            "EMAIL_FOOTER_TEXT_MARKER": (
                "Comunicazione automatica di servizio"
            ),
            "EMAIL_FOOTER_HTML_MARKER": (
                'data-mylocalcare-email-footer="true"'
            ),
            "EVENTO_ROLLOUT_INVITO": "rollout_invito",
            "EVENTO_ROLLOUT_PROMEMORIA_1": "rollout_promemoria_1",
            "EVENTO_ROLLOUT_PROMEMORIA_2": "rollout_promemoria_2",
            "EVENTO_ROLLOUT_ULTIMO_AVVISO": "rollout_ultimo_avviso",
            "EVENTO_ARCHIVIATO": "archiviato",
            "normalize_language": normalize_language,
            "translate_source": translate_source,
            "localize_html_document": localize_html_document,
            "get_db_connection": self._connect,
            "get_cursor": lambda conn: conn.cursor(),
            "sql": lambda query: query,
            "build_external_url": (
                lambda endpoint, **values: (
                    "https://www.mylocalcare.it/privacy"
                )
            ),
            "render_template": lambda *args, **kwargs: "",
            "security_log": self._log,
            "log_exception_safe": self._log,
            "socketio": SimpleNamespace(emit=lambda *args, **kwargs: None),
            "chat_count_unread": lambda user_id: 0,
            "invia_push": lambda *args, **kwargs: True,
        }
        self.backend = _load_functions(self.FUNCTIONS, namespace)
        self.env = mock.patch.dict(
            os.environ,
            {
                "POSTMARK_SERVER_TOKEN": "postmark-test-token",
                "MAIL_FROM_ADDRESS": "info@mylocalcare.it",
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp_dir.cleanup()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _log(self, *args, **kwargs):
        self.logs.append((args, kwargs))

    @property
    def last_payload(self):
        self.assertTrue(self.transport.calls)
        url, request = self.transport.calls[-1]
        self.assertEqual(url, "https://api.postmarkapp.com/email")
        self.assertEqual(request["timeout"], 15)
        return request["json"]

    def _send_copy(self, email_copy, *, destination, language=None, url):
        sent = self.backend["_invia_email"](
            destinazione=destination,
            oggetto=email_copy["oggetto"],
            corpo=email_copy["corpo"],
            action_url=url,
            action_label=email_copy["action_label"],
            language=language,
        )
        self.assertTrue(sent)
        return self.last_payload

    def test_database_language_works_without_request_or_app_context(self):
        self.assertFalse(has_app_context())
        email_copy = self.backend["_copy_email_conferma_account"](
            "NomInvariant_X9"
        )
        confirmation_url = (
            "https://www.mylocalcare.it/conferma/Token-Invariant_123"
        )
        payload = self._send_copy(
            email_copy,
            destination="FR@EXAMPLE.TEST",
            url=confirmation_url,
        )
        self.assertFalse(has_app_context())

        self.assertEqual(
            payload["Subject"],
            translate_source(email_copy["oggetto"], "fr"),
        )
        expected_lines = [
            translate_source(line, "fr")
            for line in email_copy["corpo"].splitlines()
            if line
        ]
        for line in expected_lines:
            self.assertIn(line, payload["TextBody"])

        html_body = html_module.unescape(payload["HtmlBody"])
        self.assertIn('lang="fr"', html_body)
        self.assertIn(
            translate_source(email_copy["action_label"], "fr"),
            html_body,
        )
        self.assertIn(f'href="{confirmation_url}"', html_body)
        self.assertIn("NomInvariant_X9", payload["TextBody"])
        self.assertIn("NomInvariant_X9", html_body)
        self.assertIn("Token-Invariant_123", html_body)

        marker = translate_source(
            "Comunicazione automatica di servizio",
            "fr",
        )
        privacy_notice = translate_source(
            "Informativa privacy disponibile sul sito MyLocalCare.",
            "fr",
        )
        privacy_label = translate_source("Informativa privacy", "fr")
        self.assertIn(marker, payload["TextBody"])
        self.assertIn(privacy_notice, payload["TextBody"])
        self.assertIn(marker, html_body)
        self.assertIn(privacy_label, html_body)
        self.assertNotIn(
            "Comunicazione automatica di servizio",
            payload["TextBody"],
        )
        self.assertEqual(
            payload["HtmlBody"].count(
                'data-mylocalcare-email-footer="true"'
            ),
            1,
        )
        self.assertIn(
            'href="https://www.mylocalcare.it/privacy"',
            payload["HtmlBody"],
        )

    def test_language_lookup_does_not_close_existing_background_connection(self):
        original_factory = self.backend["get_db_connection"]
        with self.app.app_context():
            connection = self._connect()
            g.db_conn = connection
            self.backend["get_db_connection"] = lambda: g.db_conn
            try:
                email_copy = self.backend["_copy_email_conferma_account"](
                    "NomInvariant_X9"
                )
                payload = self._send_copy(
                    email_copy,
                    destination="fr@example.test",
                    url="https://www.mylocalcare.it/conferma/BackgroundToken",
                )
                self.assertEqual(
                    payload["Subject"],
                    translate_source(email_copy["oggetto"], "fr"),
                )
                self.assertEqual(
                    connection.execute("SELECT 1").fetchone()[0],
                    1,
                )
                self.assertIs(g.db_conn, connection)
            finally:
                self.backend["get_db_connection"] = original_factory
                g.db_conn = None
                connection.close()

    def test_final_postmark_payload_is_complete_in_all_eight_languages(self):
        email_copy = self.backend["_copy_email_reset_password"](
            "NameInvariant_Q7"
        )
        reset_url = (
            "https://www.mylocalcare.it/reset_password/Reset-Token_Q7"
        )

        for language in SUPPORTED_LANGUAGES:
            with self.subTest(language=language):
                payload = self._send_copy(
                    email_copy,
                    destination="fr@example.test",
                    language=language,
                    url=reset_url,
                )
                self.assertEqual(
                    payload["Subject"],
                    translate_source(email_copy["oggetto"], language),
                )
                for source_line in email_copy["corpo"].splitlines():
                    if source_line:
                        self.assertIn(
                            translate_source(source_line, language),
                            payload["TextBody"],
                        )
                marker = translate_source(
                    "Comunicazione automatica di servizio",
                    language,
                )
                privacy_notice = translate_source(
                    "Informativa privacy disponibile sul sito MyLocalCare.",
                    language,
                )
                self.assertIn(marker, payload["TextBody"])
                self.assertIn(privacy_notice, payload["TextBody"])
                self.assertEqual(payload["TextBody"].count(marker), 1)

                html_body = html_module.unescape(payload["HtmlBody"])
                self.assertIn(f'lang="{language}"', html_body)
                self.assertIn(
                    translate_source(
                        email_copy["action_label"],
                        language,
                    ),
                    html_body,
                )
                self.assertIn(f'href="{reset_url}"', html_body)
                self.assertIn("NameInvariant_Q7", html_body)
                self.assertIn("Reset-Token_Q7", html_body)
                self.assertEqual(
                    payload["HtmlBody"].count(
                        'data-mylocalcare-email-footer="true"'
                    ),
                    1,
                )

    def test_html_only_fallback_and_invalid_database_language_use_italian(self):
        direct_html = (
            '<html><body><h1>Conferma account</h1>'
            '<a href="https://www.mylocalcare.it/account/HtmlToken_44">'
            "Conferma account</a></body></html>"
        )
        sent = self.backend["_invia_email"](
            destinazione="invalid@example.test",
            oggetto="Conferma account MyLocalCare",
            html=direct_html,
        )
        self.assertTrue(sent)
        payload = self.last_payload
        self.assertEqual(payload["Subject"], "Conferma account MyLocalCare")
        self.assertIn(
            "Hai ricevuto una comunicazione da MyLocalCare.",
            payload["TextBody"],
        )
        self.assertIn(
            "Apri questa email in formato HTML per visualizzarla correttamente.",
            payload["TextBody"],
        )
        self.assertIn(
            "Comunicazione automatica di servizio",
            payload["TextBody"],
        )
        self.assertIn("HtmlToken_44", payload["HtmlBody"])

        for language in SUPPORTED_LANGUAGES:
            with self.subTest(language=language):
                sent = self.backend["_invia_email"](
                    destinazione="nobody@example.test",
                    oggetto="Conferma account MyLocalCare",
                    html=direct_html,
                    language=language,
                )
                self.assertTrue(sent)
                payload = self.last_payload
                self.assertEqual(
                    payload["Subject"],
                    translate_source(
                        "Conferma account MyLocalCare",
                        language,
                    ),
                )
                fallback_title = translate_source(
                    "Hai ricevuto una comunicazione da MyLocalCare.",
                    language,
                )
                fallback_message = translate_source(
                    "Apri questa email in formato HTML per visualizzarla "
                    "correttamente.",
                    language,
                )
                marker = translate_source(
                    "Comunicazione automatica di servizio",
                    language,
                )
                self.assertIn(fallback_title, payload["TextBody"])
                self.assertIn(fallback_message, payload["TextBody"])
                self.assertIn(marker, payload["TextBody"])
                self.assertIn(marker, payload["HtmlBody"])
                self.assertEqual(payload["TextBody"].count(marker), 1)
                if language != "it":
                    self.assertNotIn(
                        "Hai ricevuto una comunicazione da MyLocalCare.",
                        payload["TextBody"],
                    )
                    self.assertNotIn(
                        "Comunicazione automatica di servizio",
                        payload["TextBody"],
                    )

    def test_chat_singular_copy_from_real_sender_is_fully_localized(self):
        sent = self.backend["invia_email_promemoria_chat"](
            destinazione="uk@example.test",
            nome="ImyaInvariant_X9",
            messaggi_non_letti=1,
            nuovi_messaggi=1,
            numero_promemoria=1,
        )
        self.assertTrue(sent)
        payload = self.last_payload
        self.assertEqual(
            payload["Subject"],
            translate_source(
                "Hai nuovi messaggi da leggere su MyLocalCare",
                "uk",
            ),
        )
        self.assertIn(
            translate_source(
                "hai un messaggio non letto su MyLocalCare.",
                "uk",
            ),
            payload["TextBody"],
        )
        self.assertNotIn(
            "hai un messaggio non letto su MyLocalCare.",
            payload["TextBody"],
        )
        self.assertIn("ImyaInvariant_X9", payload["TextBody"])
        self.assertIn("ImyaInvariant_X9", payload["HtmlBody"])

    def test_request_and_response_payload_use_recipient_language_and_cta(self):
        cases = (
            {
                "tipo_evento": "richiesta",
                "title": (
                    "Hai ricevuto una richiesta di disponibilità "
                    "su MyLocalCare"
                ),
                "message": (
                    "Un utente ti ha chiesto di confermare la disponibilità "
                    "per un tuo annuncio."
                ),
                "cta": "Visualizza richiesta",
                "link": "/chat/17?richiesta_disponibilita=91",
            },
            {
                "tipo_evento": "risposta",
                "title": "Hai ricevuto una risposta su MyLocalCare",
                "message": (
                    "L’utente ha confermato la disponibilità richiesta."
                ),
                "cta": "Visualizza risposta",
                "link": "/chat/23?risposta_disponibilita=92",
            },
        )
        sender = self.backend["_invia_canali_richiesta_disponibilita"]

        for index, case in enumerate(cases, start=1):
            for language in SUPPORTED_LANGUAGES:
                with self.subTest(
                    case=case["tipo_evento"],
                    language=language,
                ):
                    link = case["link"]
                    dispatch = {
                        "tipo_evento": case["tipo_evento"],
                        "richiesta_id": 90 + index,
                        "mittente_id": 10 + index,
                        "destinatario_id": 20 + index,
                        "destinatario_email": (
                            f"recipient-{index}-{language}@example.test"
                        ),
                        "email_notifiche": 1,
                        "language": language,
                        "link": link,
                        "titolo": translate_source(
                            "Nuova richiesta di disponibilità",
                            language,
                        ),
                        "messaggio": translate_source(
                            case["message"],
                            language,
                        ),
                        "stato": "disponibile",
                        "versione": 2,
                        "risposta_at": None,
                    }
                    sender(
                        dispatch,
                        titolo_email=case["title"],
                        cta_email=case["cta"],
                        messaggio_email_source=case["message"],
                    )
                    payload = self.last_payload
                    self.assertEqual(
                        payload["Subject"],
                        translate_source(case["title"], language),
                    )
                    self.assertIn(
                        translate_source(case["message"], language),
                        payload["TextBody"],
                    )
                    marker = translate_source(
                        "Comunicazione automatica di servizio",
                        language,
                    )
                    self.assertIn(marker, payload["TextBody"])
                    html_body = html_module.unescape(payload["HtmlBody"])
                    self.assertIn(f'lang="{language}"', html_body)
                    self.assertIn(
                        translate_source(case["cta"], language),
                        html_body,
                    )
                    self.assertIn(
                        f'href="https://www.mylocalcare.it{link}"',
                        html_body,
                    )
                    if language != "it":
                        self.assertNotIn(case["cta"], html_body)

    def test_availability_payloads_are_complete_in_all_languages(self):
        source_pairs = [
            self.backend["_copy_promemoria_disponibilita"](phase)
            for phase in ("in_scadenza", "scaduta", "ultimo_avviso")
        ]
        source_pairs.extend(
            self.backend["_copy_evento_ciclo_disponibilita"](code)
            for code in (
                "rollout_invito",
                "rollout_promemoria_1",
                "rollout_promemoria_2",
                "rollout_ultimo_avviso",
                "archiviato",
            )
        )
        action_url = (
            "https://www.mylocalcare.it/utente/dashboard"
            "?disponibilita=riconferma"
        )

        for source_title, source_message in source_pairs:
            for language in SUPPORTED_LANGUAGES:
                with self.subTest(
                    title=source_title,
                    language=language,
                ):
                    sent = self.backend["_invia_email"](
                        destinazione="recipient@example.test",
                        oggetto=source_title,
                        corpo=f"{source_title}\n\n{source_message}",
                        action_url=action_url,
                        action_label="Controlla disponibilità",
                        language=language,
                    )
                    self.assertTrue(sent)
                    payload = self.last_payload
                    translated_title = translate_source(
                        source_title,
                        language,
                    )
                    translated_message = translate_source(
                        source_message,
                        language,
                    )
                    translated_cta = translate_source(
                        "Controlla disponibilità",
                        language,
                    )
                    marker = translate_source(
                        "Comunicazione automatica di servizio",
                        language,
                    )
                    self.assertEqual(payload["Subject"], translated_title)
                    self.assertIn(translated_title, payload["TextBody"])
                    self.assertIn(translated_message, payload["TextBody"])
                    self.assertIn(marker, payload["TextBody"])
                    html_body = html_module.unescape(payload["HtmlBody"])
                    self.assertIn(f'lang="{language}"', html_body)
                    self.assertIn(translated_title, html_body)
                    self.assertIn(translated_message, html_body)
                    self.assertIn(translated_cta, html_body)
                    self.assertIn(f'href="{action_url}"', html_body)
                    self.assertEqual(
                        payload["HtmlBody"].count(
                            'data-mylocalcare-email-footer="true"'
                        ),
                        1,
                    )
                    if language != "it":
                        self.assertNotIn(source_message, payload["TextBody"])
                        self.assertNotIn(
                            "Comunicazione automatica di servizio",
                            payload["TextBody"],
                        )

    def test_availability_copy_and_ctas_are_catalog_backed_without_drift(self):
        source_pairs = [
            self.backend["_copy_promemoria_disponibilita"](phase)
            for phase in ("in_scadenza", "scaduta", "ultimo_avviso")
        ]
        source_pairs.extend(
            self.backend["_copy_evento_ciclo_disponibilita"](code)
            for code in (
                "rollout_invito",
                "rollout_promemoria_1",
                "rollout_promemoria_2",
                "rollout_ultimo_avviso",
                "archiviato",
            )
        )
        sources = [
            source
            for pair in source_pairs
            for source in pair
        ]
        sources.extend((
            "Controlla disponibilità",
            "Visualizza richiesta",
            "Visualizza risposta",
        ))

        for source in sources:
            for language in SUPPORTED_LANGUAGES:
                with self.subTest(source=source, language=language):
                    translated = translate_source(source, language)
                    self.assertTrue(str(translated).strip())
                    if language != "it":
                        self.assertNotEqual(translated, source)

        rollout_title, rollout_message = self.backend[
            "_copy_evento_ciclo_disponibilita"
        ]("rollout_promemoria_2")
        self.assertIn("indica quali annunci", rollout_message)
        self.assertNotIn("valorizza gli annunci", rollout_message)
        self.assertNotEqual(translate_source(rollout_title, "fr"), rollout_title)

        delivery_node = _function_node(
            "_consegna_eventi_ciclo_disponibilita"
        )
        push_call = next(
            node
            for node in ast.walk(delivery_node)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "invia_push"
        )
        self.assertEqual(
            [arg.id for arg in push_call.args[:3]],
            ["user_id", "title", "message"],
        )

    def test_localized_footers_are_idempotent(self):
        text_footer = self.backend["_aggiungi_footer_text_se_manca"](
            "Corpo",
            "es",
        )
        text_footer = self.backend["_aggiungi_footer_text_se_manca"](
            text_footer,
            "es",
        )
        marker = translate_source(
            "Comunicazione automatica di servizio",
            "es",
        )
        self.assertEqual(text_footer.count(marker), 1)

        html_footer = self.backend["_aggiungi_footer_html_se_manca"](
            "<html><body>Corpo</body></html>",
            "es",
        )
        html_footer = self.backend["_aggiungi_footer_html_se_manca"](
            html_footer,
            "es",
        )
        self.assertEqual(
            html_footer.count('data-mylocalcare-email-footer="true"'),
            1,
        )


if __name__ == "__main__":
    unittest.main()
