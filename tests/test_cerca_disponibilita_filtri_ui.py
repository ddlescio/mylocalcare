import unittest
from pathlib import Path

from i18n import SUPPORTED_LANGUAGES, TRANSLATIONS


ROOT = Path(__file__).resolve().parents[1]
SEARCH_TEMPLATE = ROOT / "templates" / "cerca.html"


class CercaDisponibilitaFiltriUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SEARCH_TEMPLATE.read_text(encoding="utf-8")

    def test_detailed_filters_use_expected_repeated_query_parameters(self):
        self.assertIn('name="disponibilita_giorni"', self.source)
        self.assertIn('name="disponibilita_fasce"', self.source)
        self.assertIn('name="disponibilita_dalle"', self.source)
        self.assertIn('name="disponibilita_alle"', self.source)
        self.assertIn('name="disponibilita_a_chiamata"', self.source)
        self.assertIn(
            'name="disponibilita_giorno_successivo"',
            self.source,
        )
        self.assertIn(
            "request.args.getlist('disponibilita_giorni')",
            self.source,
        )
        self.assertIn(
            "request.args.getlist('disponibilita_fasce')",
            self.source,
        )

    def test_all_days_and_broad_time_slots_are_available(self):
        for day_value in range(1, 8):
            self.assertIn(f"('{day_value}', 'availability.day_", self.source)
        for slot in ("mattina", "pomeriggio", "sera", "notte"):
            self.assertIn(f"('{slot}', 'availability.slot_", self.source)

    def test_detail_panel_is_accessible_and_tied_to_confirmed_toggle(self):
        self.assertIn(
            'aria-controls="disponibilita-filtri-dettaglio"',
            self.source,
        )
        self.assertIn(
            'id="disponibilita-filtri-dettaglio"',
            self.source,
        )
        self.assertIn(
            'aria-labelledby="disponibilita-filtri-titolo"',
            self.source,
        )
        self.assertIn('role="alert"', self.source)
        self.assertIn("aggiornaDettagliDisponibilita", self.source)
        self.assertIn("input.disabled = !attivi", self.source)

    def test_exact_time_browser_validation_requires_pair_and_day(self):
        self.assertIn("Boolean(dalle) !== Boolean(alle)", self.source)
        self.assertIn(
            'input[name="disponibilita_giorni"]:checked',
            self.source,
        )
        self.assertIn("giorniScelti.length === 0", self.source)
        self.assertIn("input.setCustomValidity(message)", self.source)
        self.assertIn("invalidInput?.reportValidity()", self.source)
        self.assertIn("event.preventDefault()", self.source)

    def test_overnight_interval_is_inferred_and_explained(self):
        self.assertIn("alleMinuti < dalleMinuti", self.source)
        self.assertIn("dalleMinuti >= (18 * 60)", self.source)
        self.assertIn("alleMinuti <= (8 * 60)", self.source)
        self.assertIn("aggiornaIndicatoreGiornoSuccessivo(true)", self.source)
        self.assertIn("availability_request.next_day", self.source)
        self.assertIn("availability_request.next_day_help", self.source)

    def test_new_copy_is_translated_in_every_supported_language(self):
        keys = (
            "search.availability_detail_title",
            "search.availability_detail_hint",
            "search.availability_days_title",
            "search.availability_days_help",
            "search.availability_slots_help",
            "search.availability_on_call_help",
            "search.availability_exact_time_title",
            "search.availability_exact_time_help",
            "search.availability_time_pair_error",
            "search.availability_time_equal_error",
            "search.availability_time_day_error",
        )
        expected_languages = set(SUPPORTED_LANGUAGES)

        for key in keys:
            with self.subTest(key=key):
                self.assertIn(key, TRANSLATIONS)
                self.assertEqual(
                    set(TRANSLATIONS[key]),
                    expected_languages,
                )
                self.assertTrue(all(TRANSLATIONS[key].values()))
                self.assertIn(f"tr('{key}')", self.source)

    def test_show_all_clears_every_availability_query_parameter(self):
        for parameter in (
            "solo_disponibili",
            "disponibilita_giorni",
            "disponibilita_fasce",
            "disponibilita_dalle",
            "disponibilita_alle",
            "disponibilita_a_chiamata",
            "disponibilita_giorno_successivo",
        ):
            with self.subTest(parameter=parameter):
                self.assertIn(
                    f'"{parameter}"',
                    self.source[
                        self.source.index("if (mostraTuttiDisponibilita)"):
                        self.source.index(
                            "/* ==========================================\n"
                            "     DISPONIBILITÀ",
                            self.source.index("if (mostraTuttiDisponibilita)"),
                        )
                    ],
                )

    def test_reset_filters_keeps_only_category(self):
        reset_handler = self.source[
            self.source.index("if (resetBtn && container)"):
            self.source.index(
                "/* ============================\n"
                "     AUTOCOMPLETE COMUNI",
                self.source.index("if (resetBtn && container)"),
            )
        ]
        self.assertIn('input[name="categoria"]', reset_handler)
        self.assertIn('url.searchParams.set("categoria", categoria)', reset_handler)
        self.assertNotIn("container.submit()", reset_handler)


if __name__ == "__main__":
    unittest.main()
