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
BASE_TEMPLATE = TEMPLATES / "base.html"
PARTIAL = TEMPLATES / "partials" / "richiesta_disponibilita_dialog.html"
AVAILABILITY_DISPLAY = (
    TEMPLATES / "partials" / "disponibilita_servizi_display.html"
)
SCRIPT = ROOT / "static" / "js" / "richiesta-disponibilita.js"
STYLES = ROOT / "static" / "css" / "richiesta-disponibilita.css"


class RichiestaDisponibilitaUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main_source = MAIN_TEMPLATE.read_text(encoding="utf-8")
        cls.base_source = BASE_TEMPLATE.read_text(encoding="utf-8")
        cls.partial_source = PARTIAL.read_text(encoding="utf-8")
        cls.availability_display_source = AVAILABILITY_DISPLAY.read_text(
            encoding="utf-8"
        )
        cls.script_source = SCRIPT.read_text(encoding="utf-8")
        cls.style_source = STYLES.read_text(encoding="utf-8")

    def test_cta_is_scoped_to_offers_and_non_owner_visitors(self):
        self.assertIn("annuncio.get('tipo_annuncio') == 'offro'", self.main_source)
        self.assertIn("g.utente['id'] != annuncio['utente_id']", self.main_source)
        self.assertIn("{% set visitatore_admin = session.get('is_admin')", self.main_source)
        self.assertIn("and not visitatore_admin", self.main_source)
        self.assertIn(
            "and disponibilita_annuncio_richiedibile|default(true)",
            self.main_source,
        )
        self.assertIn(
            "can_request=puo_richiedere_disponibilita",
            self.main_source,
        )
        self.assertIn(
            "data-availability-request-open",
            self.availability_display_source,
        )
        self.assertIn(
            'include "partials/richiesta_disponibilita_dialog.html"',
            self.main_source,
        )
        self.assertIn(
            "availability_request.open",
            self.availability_display_source,
        )

    def test_backend_requestability_controls_cta_and_dialog(self):
        app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        route_start = app_source.index("def visualizza_annuncio_pubblico(id):")
        route_end = app_source.index(
            "# --- Profilo pubblico dell’operatore ---",
            route_start,
        )
        route = app_source[route_start:route_end]

        self.assertIn("_annuncio_bloccato_dalla_disponibilita", route)
        self.assertIn("disponibilita_annuncio_richiedibile", route)
        self.assertIn(
            "{% if puo_richiedere_disponibilita %}",
            self.main_source,
        )

    def test_cta_is_inside_availability_card_not_messages_card(self):
        contact_start = self.main_source.index('id="sezione-contatto"')
        contact_end = self.main_source.index('<!-- 📞 CONTATTI -->')
        contact_section = self.main_source[contact_start:contact_end]

        self.assertNotIn("data-availability-request-open", contact_section)
        self.assertIn("availability-listing-shell", self.availability_display_source)
        self.assertIn("availability-listing-request", self.availability_display_source)
        self.assertIn('aria-haspopup="dialog"', self.availability_display_source)
        self.assertIn(
            'aria-controls="availability-request-dialog"',
            self.availability_display_source,
        )

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
        self.assertEqual(
            rendered.count('data-availability-request-day-toggle'),
            7,
        )
        self.assertEqual(
            rendered.count('data-availability-request-time-start'),
            1,
        )
        self.assertEqual(
            rendered.count('data-availability-request-time-end'),
            1,
        )
        self.assertNotIn('data-availability-request-add-interval', rendered)

    def test_ajax_form_cannot_fall_back_to_native_get(self):
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
        form_tag = rendered.split(
            '<form id="availability-request-form"', 1
        )[1].split(">", 1)[0]

        # Il loader globale intercetta i submit in capture e usa form.submit(),
        # che salta gli handler. Questo form AJAX deve quindi esserne escluso.
        self.assertIn(
            'if (form.hasAttribute("data-no-global-loader")) return;',
            self.base_source,
        )
        self.assertIn("form.submit();", self.base_source)
        self.assertIn("data-no-global-loader", form_tag)

        # Anche con lo script esterno assente o una cache HTML/JS disallineata,
        # non deve mai ricadere nel GET della pagina annuncio corrente, ne fare
        # un POST form-urlencoded verso l'API che accetta soltanto JSON.
        self.assertIn('onsubmit="return false;"', form_tag)
        self.assertIn(
            '<button type="submit"\n                id="availability-request-submit"',
            rendered,
        )
        self.assertNotIn("method=", form_tag)
        self.assertNotIn("action=", form_tag)
        self.assertIn(
            'src="/static/js/richiesta-disponibilita.js?v=20261002-1"',
            rendered,
        )

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
        self.assertIn(".availability-listing-request__button", self.style_source)
        self.assertIn("width: 100%;", self.style_source)
        self.assertIn("@media (min-width: 520px)", self.style_source)
        self.assertIn("max-height: 92vh;", self.style_source)
        self.assertIn("max-height: min(92dvh, 58rem);", self.style_source)
        self.assertLess(
            self.style_source.index("max-height: 92vh;"),
            self.style_source.index("max-height: min(92dvh, 58rem);"),
        )
        self.assertIn(".availability-request-chip.is-selected", self.style_source)
        self.assertIn('label.classList.toggle("is-selected"', self.script_source)
        self.assertIn("grid-template-columns: repeat(4", self.style_source)
        self.assertIn("grid-template-columns: repeat(7", self.style_source)
        self.assertIn("buildSharedPayload(", self.script_source)

    def test_exact_time_uses_the_same_native_mobile_controls_as_search(self):
        self.assertEqual(self.partial_source.count('type="time"'), 2)
        self.assertEqual(self.partial_source.count('step="60"'), 2)
        self.assertIn('data-availability-request-time-start', self.partial_source)
        self.assertIn('data-availability-request-time-end', self.partial_source)
        self.assertIn("const crossesMidnight", self.script_source)
        self.assertIn("updateNextDayNote();", self.script_source)
        self.assertIn("openNativeTimePicker", self.script_source)
        self.assertIn('typeof input.showPicker !== "function"', self.script_source)
        self.assertIn("input.showPicker();", self.script_source)
        self.assertIn('-webkit-appearance: auto;', self.style_source)
        self.assertIn('appearance: auto;', self.style_source)
        self.assertIn('font-size: 16px;', self.style_source)

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

    def test_backend_errors_and_shared_selection_are_visible_and_accessible(self):
        for marker in (
            'typeof data.error === "string"',
            "data.error.trim()",
            "selectedDayNumbers()",
            "selectedSlots()",
            "collectSharedPayload()",
            "validateSharedSelection(payload)",
            "showError(message, target)",
        ):
            self.assertIn(marker, self.script_source)
        self.assertIn('role="alert"', self.partial_source)
        self.assertIn('aria-describedby="availability-request-error"', self.partial_source)

    def test_missing_profile_photo_alerts_and_redirects_to_dashboard(self):
        for marker in (
            "foto_profilo_richiesta",
            "action_url",
            "alert(",
            "location",
        ):
            self.assertIn(marker, self.script_source)
        self.assertIn(
            "data-profile-photo-url=\"{{ url_for('dashboard') }}\"",
            self.partial_source,
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
    def test_submit_and_click_binding_is_retry_safe(self):
        node_program = r"""
const api = require(process.argv[1]);

class FakeTarget {
  constructor() {
    this.listeners = new Map();
  }
  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }
  removeEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    this.listeners.set(type, listeners.filter((item) => item !== listener));
  }
  dispatch(type) {
    const event = {
      type,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; }
    };
    (this.listeners.get(type) || []).slice().forEach((listener) => {
      listener(event);
    });
    return event;
  }
  count(type) {
    return (this.listeners.get(type) || []).length;
  }
}

const form = new FakeTarget();
const oldButton = new FakeTarget();
const currentButton = new FakeTarget();
const calls = [];

api.bindSubmissionHandlers(form, oldButton, () => calls.push("stale"));
api.bindSubmissionHandlers(form, currentButton, () => calls.push("current"));
api.bindSubmissionHandlers(form, currentButton, () => calls.push("latest"));

const staleClick = oldButton.dispatch("click");
const click = currentButton.dispatch("click");
const submit = form.dispatch("submit");

process.stdout.write(JSON.stringify({
  calls,
  staleClickPrevented: staleClick.defaultPrevented,
  clickPrevented: click.defaultPrevented,
  submitPrevented: submit.defaultPrevented,
  submitListeners: form.count("submit"),
  clickListeners: currentButton.count("click"),
  staleClickListeners: oldButton.count("click")
}));
"""
        completed = subprocess.run(
            [shutil.which("node"), "-e", node_program, str(SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)

        self.assertEqual(result["calls"], ["latest", "latest"])
        self.assertFalse(result["staleClickPrevented"])
        self.assertTrue(result["clickPrevented"])
        self.assertTrue(result["submitPrevented"])
        self.assertEqual(result["submitListeners"], 1)
        self.assertEqual(result["clickListeners"], 1)
        self.assertEqual(result["staleClickListeners"], 0)

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_browser_bootstrap_retries_on_pageshow_for_bfcache(self):
        node_program = r"""
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync(process.argv[1], "utf8");
const documentListeners = {};
const windowListeners = {};
const document = {
  readyState: "loading",
  addEventListener(type, listener) { documentListeners[type] = listener; }
};
const window = {
  document,
  addEventListener(type, listener) { windowListeners[type] = listener; }
};

vm.runInNewContext(source, {window});
const calls = [];
window.MyLocalCareAvailabilityRequest.init = (documentRef, options) => {
  calls.push({sameDocument: documentRef === document, restore: options.restore});
};

documentListeners.DOMContentLoaded({type: "DOMContentLoaded"});
windowListeners.pageshow({type: "pageshow", persisted: true});
windowListeners.pageshow({type: "pageshow", persisted: true});

process.stdout.write(JSON.stringify(calls));
"""
        completed = subprocess.run(
            [shutil.which("node"), "-e", node_program, str(SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )
        calls = json.loads(completed.stdout)

        self.assertEqual(
            calls,
            [
                {"sameDocument": True, "restore": False},
                {"sameDocument": True, "restore": True},
                {"sameDocument": True, "restore": True},
            ],
        )
        self.assertNotIn("__availabilityRequestReady", self.script_source)

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
const sharedPayload = api.buildSharedPayload(
  [5, 1, 3],
  ["sera", "mattina"],
  "22:00",
  "02:00",
  true
);
const onCallOnly = api.buildPayload([], true);
const result = {
  payload,
  sharedPayload,
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
        shared = result["sharedPayload"]
        self.assertTrue(shared["a_chiamata"])
        self.assertEqual(
            [day["giorno_settimana"] for day in shared["giorni"]],
            [1, 3, 5],
        )
        for day in shared["giorni"]:
            self.assertEqual(day["fasce"], ["mattina", "sera"])
            self.assertEqual(
                day["intervalli"],
                [{
                    "ora_inizio": "22:00",
                    "ora_fine": "02:00",
                    "giorno_successivo": True,
                }],
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
