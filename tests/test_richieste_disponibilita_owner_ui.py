import json
import shutil
import subprocess
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from i18n import SUPPORTED_LANGUAGES, TRANSLATIONS


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
CHAT_TEMPLATE = TEMPLATES / "chat_conversazione.html"
LISTING_TEMPLATE = TEMPLATES / "annuncio_pubblico.html"
PARTIAL = TEMPLATES / "partials" / "richieste_disponibilita_proprietario.html"
SCRIPT = ROOT / "static" / "js" / "richieste-disponibilita-proprietario.js"
STYLES = ROOT / "static" / "css" / "richieste-disponibilita-proprietario.css"


class RichiesteDisponibilitaOwnerUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chat_source = CHAT_TEMPLATE.read_text(encoding="utf-8")
        cls.listing_source = LISTING_TEMPLATE.read_text(encoding="utf-8")
        cls.partial_source = PARTIAL.read_text(encoding="utf-8")
        cls.script_source = SCRIPT.read_text(encoding="utf-8")
        cls.style_source = STYLES.read_text(encoding="utf-8")

        environment = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            autoescape=select_autoescape(("html",)),
        )
        cls.environment = environment
        cls.rendered = environment.get_template(
            "partials/richieste_disponibilita_proprietario.html"
        ).render(
            richieste_disponibilita_chat=[
                {
                    "id": 81,
                    "annuncio_id": 47,
                    "stato": "in_attesa",
                    "versione": 3,
                    "created_at": "2026-09-25T09:30:00+02:00",
                    "risposta_at": None,
                    "inviata_da_me": False,
                    "sono_offerente": True,
                    "posso_rispondere": True,
                    "conversazione_bloccata": False,
                    "a_chiamata": True,
                    "annuncio": {
                        "titolo": "Cerco babysitter serale",
                        "categoria": "Babysitter",
                        "stato": "pubblicato",
                        "url": "/annuncio/47",
                    },
                    "giorni": [
                        {
                            "giorno_settimana": 1,
                            "fasce": ["mattina", "sera"],
                            "intervalli": [
                                {
                                    "ora_inizio": "22:30",
                                    "ora_fine": "02:15",
                                    "giorno_successivo": True,
                                }
                            ],
                        }
                    ],
                }
            ],
            csrf_token=lambda: "owner-csrf-token",
            tr=lambda key, **values: key.format(**values),
            url_for=lambda endpoint, filename=None, **kwargs: (
                f"/static/{filename}" if filename else f"/{endpoint}"
            ),
        )

    def test_cards_are_wired_inside_chat_only(self):
        self.assertIn(
            'include "partials/richieste_disponibilita_proprietario.html"',
            self.chat_source,
        )
        self.assertIn("richieste_disponibilita_chat", self.chat_source)
        self.assertIn("css/richieste-disponibilita-proprietario.css", self.chat_source)
        self.assertNotIn(
            'include "partials/richieste_disponibilita_proprietario.html"',
            self.listing_source,
        )

    def test_request_card_is_closed_and_is_not_a_fake_chat_message(self):
        self.assertIn("data-owner-availability-request-details", self.rendered)
        self.assertNotIn("data-owner-availability-panel", self.rendered)
        self.assertNotIn("<details open", self.rendered)
        self.assertNotIn("data-mid=", self.rendered)
        self.assertNotIn('class="bubble', self.rendered)

    def test_card_renders_listing_schedule_on_call_and_response_endpoint(self):
        for marker in (
            'data-request-id="81"',
            'data-version="3"',
            'data-state="in_attesa"',
            'data-can-respond="1"',
            'data-chat-blocked="0"',
            'data-endpoint="/api/richieste-disponibilita/81/risposta"',
            'data-csrf-token="owner-csrf-token"',
            "Cerco babysitter serale",
            "Babysitter",
            "availability_request_chat.received_by_you",
            "availability.on_call_label",
            "availability.day_monday",
            "availability.slot_morning",
            "availability.slot_evening",
            "22:30",
            "02:15",
            "availability_request_owner.next_day_short",
            'href="/annuncio/47"',
        ):
            self.assertIn(marker, self.rendered)

        for response_state in ("disponibile", "non_disponibile", "informazioni"):
            self.assertIn(
                f'data-owner-availability-response="{response_state}"',
                self.rendered,
            )

    def test_card_does_not_render_private_contact_fields(self):
        rendered_lower = self.rendered.lower()
        for forbidden in ("email", "telefono", "phone", "whatsapp"):
            self.assertNotIn(forbidden, rendered_lower)

    def test_response_updates_in_place_and_information_focuses_composer(self):
        for marker in (
            'method: "POST"',
            'credentials: "same-origin"',
            '"Content-Type": "application/json"',
            '"X-CSRF-Token": csrfToken',
            '"X-Requested-With": "XMLHttpRequest"',
            'stato: String(state || "")',
            "versione: Number(version)",
            "card.dataset.version = String(Number(version))",
            "updateState(card, nextState, data.version)",
            'documentRef.getElementById("msgInput")',
            "messageInput?.focus({ preventScroll: true })",
            'typeof data.error === "string"',
            "data.error.trim()",
            "const message = backendError || (response.status === 409",
        ):
            self.assertIn(marker, self.script_source)
        self.assertNotIn("windowRef.location.assign", self.script_source)
        self.assertNotIn("data.chat_url", self.script_source)
        self.assertNotIn("windowRef.location.reload", self.script_source)

    def test_expired_requests_are_terminal_and_have_no_response_buttons(self):
        self.assertIn(
            "'scaduta': tr('availability_request_owner.state_expired')",
            self.partial_source,
        )
        self.assertIn('"scaduta"', self.script_source)
        self.assertIn(".owner-availability-request-status.is-scaduta", self.style_source)
        self.assertIn("{% if can_answer_request %}", self.partial_source)

        rendered = self.environment.get_template(
            "partials/richieste_disponibilita_proprietario.html"
        ).render(
            richieste_disponibilita_chat=[{
                "id": 82,
                "stato": "scaduta",
                "versione": 2,
                "inviata_da_me": True,
                "sono_offerente": False,
                "posso_rispondere": False,
                "annuncio": {"titolo": "Annuncio concluso"},
                "giorni": [],
            }],
            csrf_token=lambda: "token",
            tr=lambda key, **values: key.format(**values),
            url_for=lambda endpoint, filename=None, **kwargs: (
                f"/static/{filename}" if filename else f"/{endpoint}"
            ),
        )
        self.assertIn('data-state="scaduta"', rendered)
        self.assertIn("availability_request_owner.state_expired", rendered)
        self.assertNotIn("data-owner-availability-response=", rendered)

    def test_realtime_block_status_hides_and_restores_pending_actions(self):
        for marker in (
            'data-owner-availability-waiting',
            'data-can-respond=',
            'data-chat-blocked=',
            '"localcare:chat-block-status"',
            'syncChatBlockStatus(detail.bloccata === true)',
            'actions.hidden = !pending || !canRespond || blocked',
            'waiting.hidden = !pending || (canRespond && !blocked)',
        ):
            self.assertIn(marker, self.partial_source + self.script_source)

        self.assertIn(
            "'localcare:chat-block-status'",
            self.chat_source,
        )

    def test_deep_link_opens_exact_card_scrolls_inside_chat_and_cleans_url(self):
        for marker in (
            'params.get("richiesta_disponibilita")',
            "details.open = true",
            "windowRef.requestAnimationFrame",
            'documentRef.getElementById("msgWrap")',
            "messageWrap.contains(card)",
            "messageWrap.scrollTo",
            'url.searchParams.delete("richiesta_disponibilita")',
            "windowRef.history.replaceState",
        ):
            self.assertIn(marker, self.script_source)
        self.assertNotIn("panel.open", self.script_source)
        self.assertNotIn('documentRef.getElementById("main-navbar")', self.script_source)
        self.assertNotIn("windowRef.scrollTo", self.script_source)

    def test_mobile_first_premium_and_accessible_markers_are_present(self):
        for marker in (
            "grid-template-columns: minmax(0, 1fr);",
            ".owner-availability-request-on-call",
            "@media (min-width: 640px)",
            "@media (prefers-reduced-motion: reduce)",
            ":focus-visible",
            "max-width: 34rem",
        ):
            self.assertIn(marker, self.style_source)
        self.assertIn('role="status"', self.partial_source)
        self.assertIn('aria-live="polite"', self.partial_source)
        self.assertIn('role="alert"', self.partial_source)

    def test_owner_strings_cover_all_supported_languages(self):
        keys = sorted(
            key for key in TRANSLATIONS
            if key.startswith("availability_request_owner.")
        )
        self.assertGreaterEqual(len(keys), 20)
        expected = set(SUPPORTED_LANGUAGES)
        self.assertEqual(8, len(expected))

        for key in keys:
            self.assertEqual(expected, set(TRANSLATIONS[key]), key)
            for language in expected:
                self.assertTrue(TRANSLATIONS[key][language].strip(), (key, language))

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_javascript_builds_exact_response_payload_and_cleans_chat_deep_link(self):
        node_program = r"""
const api = require(process.argv[1]);
const result = {
  payload: api.buildResponsePayload("informazioni", 7),
  cleanUrl: api.cleanDeepLinkUrl(
    "https://mylocalcare.it/chat/12?foo=bar&richiesta_disponibilita=81#orari"
  ),
  states: api.RESPONSE_STATES,
  allowedStates: api.ALLOWED_STATES
};
process.stdout.write(JSON.stringify(result));
"""
        completed = subprocess.run(
            [shutil.which("node"), "-e", node_program, str(SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)

        self.assertEqual(
            {"stato": "informazioni", "versione": 7},
            result["payload"],
        )
        self.assertEqual("/chat/12?foo=bar#orari", result["cleanUrl"])
        self.assertEqual(
            ["disponibile", "non_disponibile", "informazioni"],
            result["states"],
        )
        self.assertIn("scaduta", result["allowedStates"])
        self.assertNotIn("scaduta", result["states"])


if __name__ == "__main__":
    unittest.main()
