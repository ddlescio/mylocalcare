import json
import shutil
import subprocess
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from i18n import SUPPORTED_LANGUAGES, TRANSLATIONS


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
MAIN_TEMPLATE = TEMPLATES / "annuncio_pubblico.html"
PARTIAL = TEMPLATES / "partials" / "richiesta_disponibilita_dialog.html"
SCRIPT = ROOT / "static" / "js" / "richiesta-disponibilita.js"
STYLES = ROOT / "static" / "css" / "richiesta-disponibilita.css"


class RichiestaDisponibilitaUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main_source = MAIN_TEMPLATE.read_text(encoding="utf-8")
        cls.partial_source = PARTIAL.read_text(encoding="utf-8")
        cls.script_source = SCRIPT.read_text(encoding="utf-8")
        cls.style_source = STYLES.read_text(encoding="utf-8")

    def test_cta_is_scoped_to_offers_and_non_owner_visitors(self):
        self.assertIn("annuncio.get('tipo_annuncio') == 'offro'", self.main_source)
        self.assertIn("g.utente['id'] != annuncio['utente_id']", self.main_source)
        self.assertIn("{% set visitatore_admin = session.get('is_admin')", self.main_source)
        self.assertIn("and not visitatore_admin", self.main_source)
        self.assertIn("data-availability-request-open", self.main_source)
        self.assertIn(
            'include "partials/richiesta_disponibilita_dialog.html"',
            self.main_source,
        )
        self.assertIn("availability_request.open", self.main_source)

    def test_dialog_renders_literal_endpoint_and_has_no_free_text(self):
        environment = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            autoescape=select_autoescape(("html",)),
        )
        rendered = environment.get_template(
            "partials/richiesta_disponibilita_dialog.html"
        ).render(
            annuncio={"id": 47},
            csrf_token=lambda: "csrf-test-token",
            tr=lambda key, **values: key.format(**values),
            url_for=lambda endpoint, filename=None, **kwargs: (
                f"/static/{filename}" if filename else f"/{endpoint}"
            ),
        )

        self.assertIn(
            'data-endpoint="/api/annunci/47/richieste-disponibilita"',
            rendered,
        )
        self.assertIn('data-csrf-token="csrf-test-token"', rendered)
        self.assertNotIn("<textarea", rendered)
        self.assertNotIn('name="messaggio"', rendered)
        self.assertNotIn('name="note"', rendered)
        self.assertIn('data-availability-request-on-call', rendered)

    def test_dialog_is_accessible_and_mobile_first(self):
        for marker in (
            'role="dialog"',
            'aria-modal="true"',
            'aria-labelledby="availability-request-title"',
            'aria-describedby="availability-request-subtitle"',
            'role="alert"',
            'aria-live="polite"',
        ):
            self.assertIn(marker, self.partial_source)

        self.assertIn('event.key === "Escape"', self.script_source)
        self.assertIn("event.target === dialog", self.script_source)
        self.assertIn('event.key !== "Tab"', self.script_source)
        self.assertIn('classList.add("overflow-hidden", "modal-open")', self.script_source)
        self.assertIn("grid-template-columns: minmax(0, 1fr);", self.style_source)
        self.assertIn("@media (min-width: 520px)", self.style_source)
        self.assertIn("max-height: 92vh;", self.style_source)
        self.assertIn("max-height: min(92dvh, 58rem);", self.style_source)
        self.assertLess(
            self.style_source.index("max-height: 92vh;"),
            self.style_source.index("max-height: min(92dvh, 58rem);"),
        )
        self.assertIn(".availability-request-slot.is-selected", self.style_source)
        self.assertIn('label.classList.toggle("is-selected"', self.script_source)
        self.assertIn("refreshSlotVisualStates();", self.script_source)

    def test_post_uses_json_csrf_and_exact_payload_fields(self):
        for marker in (
            'method: "POST"',
            'credentials: "same-origin"',
            '"Content-Type": "application/json"',
            '"X-CSRF-Token": csrfToken',
            '"X-Requested-With": "XMLHttpRequest"',
            "body: JSON.stringify(payload)",
            "a_chiamata:",
            "giorno_settimana:",
            "fasce:",
            "intervalli:",
            "ora_inizio:",
            "ora_fine:",
            "giorno_successivo:",
        ):
            self.assertIn(marker, self.script_source)

    def test_backend_error_and_interval_limits_are_visible_and_accessible(self):
        for marker in (
            'typeof data.error === "string"',
            "data.error.trim()",
            "MAX_INTERVALS_PER_DAY = 8",
            "MAX_INTERVALS_TOTAL = 28",
            'return "limit_per_day"',
            'return "limit_total"',
            'button.setAttribute("aria-disabled", code ? "true" : "false")',
            "showError(messageForLimit(limitCode), addButton)",
        ):
            self.assertIn(marker, self.script_source)
        self.assertIn(
            "availability_request.error_limit_per_day",
            self.partial_source,
        )
        self.assertIn(
            "availability_request.error_limit_total",
            self.partial_source,
        )
        self.assertIn(
            '.availability-request-add-interval[aria-disabled="true"]',
            self.style_source,
        )

    def test_every_new_string_has_all_eight_languages(self):
        keys = sorted(
            key for key in TRANSLATIONS
            if key.startswith("availability_request.")
        )
        self.assertGreaterEqual(len(keys), 20)
        expected = set(SUPPORTED_LANGUAGES)

        for key in keys:
            self.assertEqual(set(TRANSLATIONS[key]), expected, key)
            for language in expected:
                self.assertTrue(TRANSLATIONS[key][language].strip(), (key, language))

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_javascript_builds_and_validates_the_exact_payload(self):
        node_program = r"""
const api = require(process.argv[1]);
const interval = {
  ora_inizio: "09:00",
  ora_fine: "10:00",
  giorno_successivo: false
};
const payload = api.buildPayload([
  {
    selected: true,
    giorno_settimana: 4,
    fasce: ["notte", "mattina"],
    intervalli: [{
      ora_inizio: "22:30",
      ora_fine: "02:15",
      giorno_successivo: true
    }]
  },
  {
    selected: false,
    giorno_settimana: 2,
    fasce: ["sera"],
    intervalli: []
  },
  {
    selected: true,
    giorno_settimana: 1,
    fasce: [],
    intervalli: [{
      ora_inizio: "09:00",
      ora_fine: "11:00",
      giorno_successivo: false
    }]
  }
], true);
const onCallOnly = api.buildPayload([], true);
const result = {
  payload,
  valid: api.validatePayload(payload),
  onCallOnly,
  onCallOnlyValid: api.validatePayload(onCallOnly),
  empty: api.validatePayload({a_chiamata: false, giorni: []}),
  invalidOnCall: api.validatePayload({a_chiamata: "true", giorni: []}),
  invalidNight: api.validatePayload({giorni: [{
    giorno_settimana: 1,
    fasce: [],
    intervalli: [{
      ora_inizio: "15:00",
      ora_fine: "02:00",
      giorno_successivo: true
    }]
  }]}),
  dayLimit: api.validatePayload({giorni: [{
    giorno_settimana: 1,
    fasce: [],
    intervalli: Array.from({length: 9}, () => ({...interval}))
  }]}),
  totalLimit: api.validatePayload({giorni: [1, 2, 3, 4].map((day, index) => ({
    giorno_settimana: day,
    fasce: [],
    intervalli: Array.from({length: index === 3 ? 5 : 8}, () => ({...interval}))
  }))}),
  addDayLimit: api.intervalLimitCode(8, 8),
  addTotalLimit: api.intervalLimitCode(4, 28),
  limits: [api.MAX_INTERVALS_PER_DAY, api.MAX_INTERVALS_TOTAL]
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
        payload = result["payload"]

        self.assertEqual(list(payload), ["a_chiamata", "giorni"])
        self.assertTrue(payload["a_chiamata"])
        self.assertEqual(
            [day["giorno_settimana"] for day in payload["giorni"]],
            [1, 4],
        )
        self.assertEqual(
            set(payload["giorni"][0]),
            {"giorno_settimana", "fasce", "intervalli"},
        )
        self.assertEqual(
            payload["giorni"][1]["fasce"],
            ["mattina", "notte"],
        )
        self.assertEqual(
            set(payload["giorni"][1]["intervalli"][0]),
            {"ora_inizio", "ora_fine", "giorno_successivo"},
        )
        self.assertIsNone(result["valid"])
        self.assertEqual(
            result["onCallOnly"],
            {"a_chiamata": True, "giorni": []},
        )
        self.assertIsNone(result["onCallOnlyValid"])
        self.assertEqual(result["empty"]["code"], "select_day")
        self.assertEqual(result["invalidOnCall"]["code"], "invalid_on_call")
        self.assertEqual(
            result["invalidNight"]["code"],
            "invalid_night_interval",
        )
        self.assertEqual("limit_per_day", result["dayLimit"]["code"])
        self.assertEqual("limit_total", result["totalLimit"]["code"])
        self.assertEqual("limit_per_day", result["addDayLimit"])
        self.assertEqual("limit_total", result["addTotalLimit"])
        self.assertEqual([8, 28], result["limits"])


if __name__ == "__main__":
    unittest.main()
