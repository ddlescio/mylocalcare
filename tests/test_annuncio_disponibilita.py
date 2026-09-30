import json
import shutil
import subprocess
import unittest
from pathlib import Path

from annuncio_disponibilita import (
    deserialize_sought_availability,
    listing_availability_from_form,
    listing_offer_status_from_form,
    normalize_listing_availability,
    request_to_service_availability,
    serialize_sought_availability,
    sought_availability_for_display,
)


ROOT = Path(__file__).resolve().parents[1]


class ListingAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "a_chiamata": True,
            "giorni": [
                {
                    "giorno_settimana": 1,
                    "fasce": ["mattina", "sera"],
                    "intervalli": [
                        {
                            "ora_inizio": "09:30",
                            "ora_fine": "12:00",
                            "giorno_successivo": False,
                        }
                    ],
                },
                {
                    "giorno_settimana": 5,
                    "fasce": ["pomeriggio"],
                    "intervalli": [],
                },
            ],
        }

    def test_empty_value_is_optional(self):
        self.assertIsNone(normalize_listing_availability(""))
        self.assertIsNone(normalize_listing_availability(None))

    def test_invalid_json_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_listing_availability("{not-json")

    def test_offer_conversion_uses_service_shape(self):
        result = request_to_service_availability(self.payload)
        self.assertEqual(result["stato"], "disponibile")
        self.assertTrue(result["a_chiamata"])
        self.assertEqual(
            result["settimanale"],
            [
                {"giorno_settimana": 1, "fascia": "mattina"},
                {"giorno_settimana": 1, "fascia": "sera"},
                {"giorno_settimana": 5, "fascia": "pomeriggio"},
            ],
        )
        self.assertEqual(result["settimanale_intervalli"][0]["ora_inizio"], "09:30")

    def test_offer_status_defaults_to_available_and_accepts_all_three_states(self):
        self.assertEqual(listing_offer_status_from_form({}), "disponibile")
        for status in ("disponibile", "limitata", "non_disponibile"):
            with self.subTest(status=status):
                self.assertEqual(
                    listing_offer_status_from_form({
                        "disponibilita_annuncio_stato": status,
                    }),
                    status,
                )
        with self.assertRaisesRegex(ValueError, "stato"):
            listing_offer_status_from_form({
                "disponibilita_annuncio_stato": "inventato",
            })

    def test_offer_can_be_available_without_optional_schedule_details(self):
        result = request_to_service_availability(
            {"a_chiamata": False, "giorni": []},
            stato="disponibile",
        )
        self.assertEqual(result, {
            "stato": "disponibile",
            "a_chiamata": False,
            "settimanale": [],
            "settimanale_intervalli": [],
            "date_speciali": [],
            "assenze": [],
        })

    def test_unavailable_offer_cannot_remain_on_call(self):
        result = request_to_service_availability(
            {"a_chiamata": True, "giorni": []},
            stato="non_disponibile",
        )
        self.assertEqual(result["stato"], "non_disponibile")
        self.assertFalse(result["a_chiamata"])

    def test_sought_round_trip_is_canonical(self):
        serialized = serialize_sought_availability(self.payload)
        self.assertEqual(deserialize_sought_availability(serialized), self.payload)
        self.assertEqual(json.loads(serialized), self.payload)

    def test_corrupt_persisted_value_does_not_break_public_page(self):
        self.assertIsNone(deserialize_sought_availability("broken"))
        self.assertIsNone(sought_availability_for_display("broken"))

    def test_display_shape_keeps_requested_schedule(self):
        result = sought_availability_for_display(
            serialize_sought_availability(self.payload)
        )
        self.assertEqual(result["tipo_disponibilita"], "cercata")
        self.assertTrue(result["configurata"])
        self.assertEqual(result["settimanale"][0]["giorno_settimana"], 1)

    def test_form_fallback_rebuilds_visible_controls_without_javascript(self):
        result = listing_availability_from_form({
            "disponibilita_annuncio_json": "",
            "disponibilita_annuncio_giorni": ["5", "1"],
            "disponibilita_annuncio_fasce": ["sera", "mattina"],
            "disponibilita_annuncio_dalle": "22:00",
            "disponibilita_annuncio_alle": "02:00",
            "disponibilita_annuncio_a_chiamata": "1",
        })

        self.assertTrue(result["a_chiamata"])
        self.assertEqual(
            [day["giorno_settimana"] for day in result["giorni"]],
            [1, 5],
        )
        self.assertEqual(result["giorni"][0]["fasce"], ["mattina", "sera"])
        self.assertEqual(
            result["giorni"][0]["intervalli"],
            [{
                "ora_inizio": "22:00",
                "ora_fine": "02:00",
                "giorno_successivo": True,
            }],
        )

    def test_form_fallback_allows_on_call_without_days(self):
        result = listing_availability_from_form({
            "disponibilita_annuncio_json": "",
            "disponibilita_annuncio_a_chiamata": "on",
        })
        self.assertEqual(result, {"a_chiamata": True, "giorni": []})

    def test_form_fallback_rejects_slots_or_times_without_days(self):
        for visible_values in (
            {
                "disponibilita_annuncio_fasce": ["sera"],
                "disponibilita_annuncio_a_chiamata": "1",
            },
            {
                "disponibilita_annuncio_dalle": "09:00",
                "disponibilita_annuncio_alle": "12:00",
                "disponibilita_annuncio_a_chiamata": "1",
            },
        ):
            with self.subTest(visible_values=visible_values):
                with self.assertRaisesRegex(ValueError, "almeno un giorno"):
                    listing_availability_from_form({
                        "disponibilita_annuncio_json": "",
                        **visible_values,
                    })

    def test_form_json_remains_authoritative_when_present(self):
        result = listing_availability_from_form({
            "disponibilita_annuncio_json": json.dumps(self.payload),
            "disponibilita_annuncio_fasce": ["valore-manomesso"],
        })
        self.assertEqual(result, self.payload)

    def test_new_listing_uses_fallback_and_preserves_calendar_exceptions(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn(
            "listing_availability_from_form(request.form)",
            source,
        )
        self.assertIn("preserve_calendar_exceptions=True", source)

    def test_new_offer_always_creates_default_available_category_profile(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        route_start = source.index("def nuovo_annuncio():")
        route_end = source.index("\n@app.context_processor", route_start)
        route = source[route_start:route_end]

        self.assertIn("listing_offer_status_from_form(request.form)", route)
        self.assertIn(
            'disponibilita_annuncio_input or {\n'
            '                        "a_chiamata": False,\n'
            '                        "giorni": [],',
            route,
        )
        self.assertIn("if disponibilita_offerta:", route)
        self.assertIn("_salva_disponibilita_categoria(", route)
        self.assertIn("_reset_ciclo_disponibilita_annunci(", route)
        self.assertIn(
            'stato_disponibilita=disponibilita_offerta["stato"]',
            route,
        )

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_javascript_rejects_day_bound_values_without_a_day(self):
        javascript = r"""
const fs = require("fs");
const vm = require("vm");
const sandbox = {
  window: {},
  document: { readyState: "loading", addEventListener() {} }
};
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf8"), sandbox);
const rules = sandbox.window.MyLocalCareListingAvailabilityRules;
let validateCalls = 0;
const api = {
  buildSharedPayload(days, slots, start, end, onCall) {
    return { days, slots, start, end, onCall };
  },
  validatePayload() {
    validateCalls += 1;
    return null;
  }
};
const results = [
  rules.validateSharedSelection(api, [], ["sera"], "", "", true),
  rules.validateSharedSelection(api, [], [], "09:00", "12:00", true),
  rules.validateSharedSelection(api, [], [], "", "", true),
  rules.validateSharedSelection(api, [1], ["sera"], "", "", true)
];
process.stdout.write(JSON.stringify({ results, validateCalls }));
"""
        completed = subprocess.run(
            [
                shutil.which("node"),
                "-e",
                javascript,
                str(ROOT / "static/js/annuncio-disponibilita.js"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["results"][:2], [
            {"code": "select_day"},
            {"code": "select_day"},
        ])
        self.assertEqual(result["results"][2:], [None, None])
        self.assertEqual(result["validateCalls"], 2)


if __name__ == "__main__":
    unittest.main()
