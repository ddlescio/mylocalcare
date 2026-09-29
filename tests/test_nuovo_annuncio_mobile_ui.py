import unittest
from pathlib import Path


class NuovoAnnuncioMobileUiTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    @classmethod
    def setUpClass(cls):
        cls.source = (cls.ROOT / "templates" / "nuovo_annuncio.html").read_text(
            encoding="utf-8"
        )

    def test_mobile_fields_do_not_trigger_ios_focus_zoom(self):
        self.assertIn(".new-listing-page", self.source)
        self.assertIn('font-size: 16px !important;', self.source)
        self.assertIn('overflow-x: clip;', self.source)
        self.assertNotIn("user-scalable=no", self.source)

    def test_form_uses_compact_scoped_sections(self):
        self.assertIn('class="new-listing-form ', self.source)
        self.assertGreaterEqual(self.source.count("listing-form-section"), 5)
        self.assertIn('id="descrizione" name="descrizione" rows="4"', self.source)
        self.assertIn("#annuncio-form > .listing-form-section", self.source)

    def test_compact_media_warning_keeps_essential_safety_information(self):
        self.assertIn("new-listing-media-safety", self.source)
        self.assertIn("numeri di telefono", self.source)
        self.assertIn("Le immagini vengono verificate prima della pubblicazione", self.source)

    def test_availability_picker_is_inside_content_below_description(self):
        section_two_start = self.source.index("2 · Contenuto annuncio")
        section_three_start = self.source.index("3 · Dettagli e contatti")
        section_two = self.source[section_two_start:section_three_start]

        include = "{% include 'partials/annuncio_disponibilita_picker.html' %}"
        self.assertEqual(self.source.count(include), 1)
        self.assertIn(include, section_two)
        self.assertLess(section_two.index('id="descrizione"'), section_two.index(include))

    def test_availability_picker_keeps_single_json_field_and_script_hooks(self):
        partial = (
            self.ROOT
            / "templates"
            / "partials"
            / "annuncio_disponibilita_picker.html"
        ).read_text(encoding="utf-8")

        self.assertEqual(partial.count('name="disponibilita_annuncio_json"'), 1)
        self.assertEqual(partial.count("data-listing-availability-json"), 1)
        self.assertIn('type="time"', partial)
        self.assertIn('step="60"', partial)
        self.assertIn("data-listing-availability", partial)


if __name__ == "__main__":
    unittest.main()
