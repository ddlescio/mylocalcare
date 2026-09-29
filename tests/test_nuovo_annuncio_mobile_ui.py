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


if __name__ == "__main__":
    unittest.main()
