import unittest

from i18n import (
    SUPPORTED_LANGUAGES,
    TRANSLATIONS,
    normalize_language,
    translate,
)


class InterfaceTranslationsTest(unittest.TestCase):
    def test_all_registered_keys_have_every_supported_language(self):
        expected = set(SUPPORTED_LANGUAGES)

        for key, variants in TRANSLATIONS.items():
            self.assertEqual(
                set(variants),
                expected,
                f"Traduzioni incomplete per {key}",
            )

    def test_language_codes_are_normalized(self):
        self.assertEqual(normalize_language("en-US"), "en")
        self.assertEqual(normalize_language("FR_fr"), "fr")
        self.assertEqual(normalize_language("unsupported"), "it")

    def test_unknown_key_has_safe_fallback(self):
        self.assertEqual(translate("missing.key", "de"), "missing.key")


if __name__ == "__main__":
    unittest.main()
