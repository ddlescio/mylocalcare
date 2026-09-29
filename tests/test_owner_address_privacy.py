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

    def test_email_footer_uses_brand_contact_and_privacy_without_owner_data(self):
        template = (ROOT / "templates" / "email" / "base_email.html").read_text(
            encoding="utf-8"
        )
        app_source = (ROOT / "app.py").read_text(encoding="utf-8")

        for source in (template, app_source):
            self.assertNotIn("Davide Lescio", source)
            self.assertIn("Comunicazione automatica di servizio", source)
            self.assertIn("info@mylocalcare.it", source)

        self.assertIn('data-mylocalcare-email-footer="true"', template)
        self.assertIn("Informativa privacy", template)
        self.assertNotIn("EMAIL_LEGAL_NAME", app_source)
        self.assertNotIn("EMAIL_PHYSICAL_ADDRESS", app_source)
        self.assertIn("MAIL_FROM_NAME = 'MyLocalCare'", app_source)
        self.assertNotIn('os.getenv("MAIL_FROM_NAME"', app_source)
        self.assertNotIn("os.getenv('MAIL_FROM_NAME'", app_source)

    def test_owner_identity_remains_in_the_privacy_notice(self):
        privacy = (ROOT / "templates" / "privacy.html").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "Il titolare del trattamento è Davide Lescio",
            privacy,
        )

    def test_translation_catalog_remains_valid_json(self):
        with (ROOT / "extra_translations.json").open(encoding="utf-8") as handle:
            json.load(handle)


if __name__ == "__main__":
    unittest.main()
