import ast
import shutil
import sqlite3
import subprocess
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from werkzeug.datastructures import MultiDict

from annuncio_disponibilita import listing_availability_from_form


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
SCRIPT = ROOT / "static" / "js" / "annuncio-disponibilita.js"


def _function_node(name):
    return next(
        node
        for node in ast.parse(APP_SOURCE).body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


class ModificaAnnuncioDisponibilitaTest(unittest.TestCase):
    def test_admin_type_change_clears_sought_data_across_transitions(self):
        function = _function_node("admin_annuncio_tipo")
        update_call = next(
            call
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "execute"
            and call.args
            and isinstance(call.args[0], ast.Call)
            and call.args[0].args
            and isinstance(call.args[0].args[0], ast.Constant)
            and "UPDATE annunci" in call.args[0].args[0].value
        )
        update_sql = update_call.args[0].args[0].value
        self.assertIn("ELSE NULL", update_sql)

        values = update_call.args[1]
        self.assertIsInstance(values, ast.Tuple)
        self.assertEqual(
            [value.id for value in values.elts],
            ["tipo_annuncio", "tipo_annuncio", "id"],
        )

        conn = sqlite3.connect(":memory:")
        conn.execute("""
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                tipo_annuncio TEXT NOT NULL,
                disponibilita_cercata_json TEXT
            )
        """)
        conn.executemany(
            "INSERT INTO annunci VALUES (?, ?, ?)",
            (
                (1, "cerco", '{"old":true}'),
                (2, "offro", '{"legacy":true}'),
                (3, "cerco", '{"keep":true}'),
            ),
        )

        conn.execute(update_sql, ("offro", "offro", 1))
        conn.execute(update_sql, ("cerco", "cerco", 1))
        conn.execute(update_sql, ("cerco", "cerco", 2))
        conn.execute(update_sql, ("cerco", "cerco", 3))

        rows = dict(conn.execute(
            "SELECT id, disponibilita_cercata_json FROM annunci ORDER BY id"
        ))
        self.assertIsNone(rows[1])
        self.assertIsNone(rows[2])
        self.assertEqual(rows[3], '{"keep":true}')

    def test_edit_route_persists_sought_value_and_supplies_safe_initial_state(self):
        function = _function_node("modifica_annuncio")
        route_source = ast.get_source_segment(APP_SOURCE, function)

        self.assertIn(
            "listing_availability_from_form(request.form)",
            route_source,
        )
        self.assertIn(
            'if tipo_annuncio == "cerco":',
            route_source,
        )
        self.assertIn("disponibilita_cercata_json = None", route_source)
        self.assertNotIn("serialize_sought_availability_for_listing", route_source)

        fallback_calls = [
            call
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "listing_availability_from_form"
        ]
        self.assertEqual(len(fallback_calls), 1)
        cerco_branch = next(
            branch
            for branch in ast.walk(function)
            if isinstance(branch, ast.If)
            and isinstance(branch.test, ast.Compare)
            and ast.unparse(branch.test) == "tipo_annuncio == 'cerco'"
            and fallback_calls[0] in list(ast.walk(branch))
        )
        self.assertIn(fallback_calls[0], list(ast.walk(cerco_branch)))
        self.assertIn(
            'deserialize_sought_availability(\n'
            '            annuncio["disponibilita_cercata_json"]',
            route_source,
        )
        self.assertIn(
            "listing_availability_initial=listing_availability_initial",
            route_source,
        )

        update_call = next(
            call
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "execute"
            and call.args
            and isinstance(call.args[0], ast.Call)
            and call.args[0].args
            and isinstance(call.args[0].args[0], ast.Constant)
            and "UPDATE annunci" in call.args[0].args[0].value
        )
        update_sql = update_call.args[0].args[0].value
        self.assertIn("disponibilita_cercata_json = ?", update_sql)

        values = update_call.args[1]
        self.assertIsInstance(values, ast.Tuple)
        self.assertEqual(
            [value.id for value in values.elts[-2:]],
            ["disponibilita_cercata_json", "id"],
        )

    def test_edit_form_fallback_rejects_slot_without_any_day(self):
        form = MultiDict([
            ("disponibilita_annuncio_json", ""),
            ("disponibilita_annuncio_fasce", "sera"),
            ("disponibilita_annuncio_a_chiamata", "1"),
        ])

        with self.assertRaisesRegex(ValueError, "almeno un giorno"):
            listing_availability_from_form(form)

    def test_edit_template_loads_picker_assets_and_validates_before_submit(self):
        source = (TEMPLATES / "modifica_annuncio.html").read_text(
            encoding="utf-8"
        )

        for expected in (
            "css/richiesta-disponibilita.css",
            "css/annuncio-disponibilita.css",
            "partials/annuncio_disponibilita_picker.html",
            "js/richiesta-disponibilita.js",
            "js/annuncio-disponibilita.js",
            "MyLocalCareListingAvailability.validateBeforeSubmit()",
            "listing_availability_sought_only = true",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)

        create_source = (TEMPLATES / "nuovo_annuncio.html").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("listing_availability_sought_only = true", create_source)

    def test_picker_serializes_initial_state_without_raw_html_injection(self):
        environment = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            autoescape=select_autoescape(("html", "xml")),
        )
        template = environment.get_template(
            "partials/annuncio_disponibilita_picker.html"
        )
        payload = {
            "a_chiamata": True,
            "giorni": [{
                "giorno_settimana": 2,
                "fasce": ["mattina"],
                "intervalli": [{
                    "ora_inizio": "09:15",
                    "ora_fine": "11:45",
                    "giorno_successivo": False,
                }],
            }],
            "probe": "</script><script>alert(1)</script>",
        }

        rendered = template.render(
            tr=lambda key, **kwargs: key,
            current_tipo_annuncio="cerco",
            listing_availability_initial=payload,
            listing_availability_sought_only=True,
        )

        self.assertIn("data-listing-availability-initial", rendered)
        self.assertIn('data-listing-availability-sought-only="true"', rendered)
        self.assertIn("data-listing-availability-json", rendered)
        self.assertRegex(
            rendered,
            r'name="disponibilita_annuncio_json"\s+value=""',
        )
        self.assertIn('"giorno_settimana": 2', rendered)
        self.assertNotIn("</script><script>alert(1)</script>", rendered)
        self.assertIn(r"\u003c/script\u003e", rendered)
        self.assertRegex(
            rendered,
            r'name="disponibilita_annuncio_giorni"\s+value="2"\s+checked',
        )
        self.assertRegex(
            rendered,
            r'name="disponibilita_annuncio_fasce"\s+value="mattina"\s+checked',
        )
        self.assertRegex(
            rendered,
            r'name="disponibilita_annuncio_a_chiamata"\s+value="1"\s+checked',
        )
        self.assertRegex(
            rendered,
            r'name="disponibilita_annuncio_dalle"\s+value="09:15"',
        )
        self.assertRegex(
            rendered,
            r'name="disponibilita_annuncio_alle"\s+value="11:45"',
        )
        self.assertRegex(
            rendered,
            r'data-listing-availability-sought-only="true"[\s\S]*?\bopen>',
        )

        rendered_offer = template.render(
            tr=lambda key, **kwargs: key,
            current_tipo_annuncio="offro",
            listing_availability_sought_only=True,
        )
        self.assertRegex(
            rendered_offer,
            r'data-listing-availability-sought-only="true"[\s\S]*?\bhidden',
        )

    def test_public_sought_detail_has_complete_scoped_styles(self):
        css = (
            ROOT / "static" / "css" / "disponibilita-servizi-display.css"
        ).read_text(encoding="utf-8")

        for selector in (
            ".sought-availability-listing {",
            ".sought-availability-listing .availability-listing__panel",
            ".sought-availability-listing .availability-listing__head",
            ".sought-availability-listing .availability-listing__icon",
            ".sought-availability-listing .availability-detail.is-compact",
            ".sought-availability-listing .availability-detail__week",
        ):
            with self.subTest(selector=selector):
                self.assertIn(selector, css)

        self.assertRegex(
            css,
            r"@media \(min-width: 640px\)[\s\S]*?"
            r"\.sought-availability-listing",
        )

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_picker_hydrates_existing_value_and_reset_really_clears_it(self):
        node_program = r"""
const assert = require("assert");
const script = process.argv[1];
function element(extra) {
  return Object.assign({
    checked: false,
    value: "",
    hidden: false,
    textContent: "",
    listeners: {},
    addEventListener(name, callback) { this.listeners[name] = callback; },
    scrollIntoView() {}
  }, extra || {});
}
const hidden = element();
const days = [element({ value: "1" }), element({ value: "3" })];
const slots = [element({ value: "mattina" }), element({ value: "sera" })];
const onCall = element();
const start = element();
const end = element();
const reset = element();
const errorBox = element();
const nextDay = element();
const title = element();
const hint = element();
const summary = element();
const initial = {
  a_chiamata: true,
  giorni: [1, 3].map((day) => ({
    giorno_settimana: day,
    fasce: ["mattina"],
    intervalli: [{
      ora_inizio: "09:15",
      ora_fine: "11:45",
      giorno_successivo: false
    }]
  }))
};
const initialNode = element({ textContent: JSON.stringify(initial) });
const selectors = new Map([
  ["[data-listing-availability-json]", hidden],
  ["[data-listing-availability-on-call]", onCall],
  ["[data-listing-availability-start]", start],
  ["[data-listing-availability-end]", end],
  ["[data-listing-availability-reset]", reset],
  ["[data-listing-availability-error]", errorBox],
  ["[data-listing-availability-next-day]", nextDay],
  ["[data-listing-availability-title]", title],
  ["[data-listing-availability-hint]", hint],
  ["[data-listing-availability-summary]", summary],
  ["[data-listing-availability-initial]", initialNode]
]);
const container = element({
  open: true,
  dataset: { listingAvailabilitySoughtOnly: "true" },
  querySelector(selector) { return selectors.get(selector) || null; },
  querySelectorAll(selector) {
    if (selector === "[data-listing-availability-day]") return days;
    if (selector === "[data-listing-availability-slot]") return slots;
    return [];
  }
});
const type = element({ value: "cerco", checked: true });
const copyNode = element({ textContent: JSON.stringify({
  seekTitle: "Cerco", seekHint: "Quando serve", generic: "Errore"
}) });
global.document = {
  readyState: "complete",
  querySelector(selector) {
    if (selector === "[data-listing-availability]") return container;
    if (selector === 'input[name="tipo_annuncio"]:checked') return type;
    return null;
  },
  querySelectorAll(selector) {
    return selector === 'input[name="tipo_annuncio"]' ? [type] : [];
  },
  getElementById(id) {
    return id === "listing-availability-copy" ? copyNode : null;
  }
};
global.window = {
  MyLocalCareAvailabilityRequest: {
    validatePayload(payload) {
      return payload && (payload.a_chiamata || payload.giorni.length)
        ? null : { code: "select_day" };
    },
    buildSharedPayload(dayNumbers, selectedSlots, from, to, aChiamata) {
      const intervals = from || to ? [{
        ora_inizio: from, ora_fine: to, giorno_successivo: false
      }] : [];
      return {
        a_chiamata: aChiamata,
        giorni: dayNumbers.map((day) => ({
          giorno_settimana: day,
          fasce: selectedSlots.slice(),
          intervalli: intervals.slice()
        }))
      };
    },
    timeToMinutes(value) {
      if (!value) return null;
      const parts = value.split(":").map(Number);
      return parts[0] * 60 + parts[1];
    }
  }
};
require(script);
assert.deepStrictEqual(JSON.parse(hidden.value), initial);
assert(days.every((item) => item.checked));
assert.strictEqual(slots[0].checked, true);
assert.strictEqual(slots[1].checked, false);
assert.strictEqual(start.value, "09:15");
assert.strictEqual(end.value, "11:45");
assert.strictEqual(onCall.checked, true);
assert.strictEqual(window.MyLocalCareListingAvailability.validateBeforeSubmit(), true);
reset.listeners.click();
assert.strictEqual(hidden.value, "");
type.value = "offro";
type.listeners.change();
assert.strictEqual(container.hidden, true);
assert.strictEqual(window.MyLocalCareListingAvailability.validateBeforeSubmit(), true);
type.value = "cerco";
type.listeners.change();
assert.strictEqual(container.hidden, false);
"""
        subprocess.run(
            [shutil.which("node"), "-e", node_program, str(SCRIPT)],
            check=True,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
