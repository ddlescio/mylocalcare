import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OwnerAddressPrivacyTest(unittest.TestCase):
    def test_private_street_is_not_hardcoded_in_user_facing_sources(self):
        public_sources = (
            ROOT / "app.py",
            ROOT / "i18n_catalog.py",
            ROOT / "extra_translations.json",
            ROOT / "templates" / "email" / "base_email.html",
            ROOT / "templates" / "privacy.html",
        )

        for path in public_sources:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("Via Pasubio", source)

    def test_email_footer_keeps_sender_and_privacy_link_without_street(self):
        template = (ROOT / "templates" / "email" / "base_email.html").read_text(
            encoding="utf-8"
        )
        app_source = (ROOT / "app.py").read_text(encoding="utf-8")

        self.assertIn("MyLocalCare - Davide Lescio", template)
        self.assertIn("Informativa privacy", template)
        self.assertNotIn("EMAIL_PHYSICAL_ADDRESS", app_source)

    def test_translation_catalog_remains_valid_json(self):
        with (ROOT / "extra_translations.json").open(encoding="utf-8") as handle:
            json.load(handle)


if __name__ == "__main__":
    unittest.main()
