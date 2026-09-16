import unittest

from i18n import (
    SOURCE_TRANSLATIONS,
    SUPPORTED_LANGUAGES,
    TRANSLATIONS,
    frontend_pattern_catalog,
    frontend_source_catalog,
    localize_html_document,
    normalize_language,
    translate,
    translate_source,
)
from i18n_catalog import PHRASE_ROWS


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

    def test_source_catalog_has_every_supported_language(self):
        expected = set(SUPPORTED_LANGUAGES)

        for source, variants in SOURCE_TRANSLATIONS.items():
            self.assertEqual(
                set(variants),
                expected,
                f"Traduzioni incomplete per la frase {source!r}",
            )

    def test_source_catalog_has_no_duplicate_phrases(self):
        sources = [row[0] for row in PHRASE_ROWS]
        self.assertEqual(len(sources), len(set(sources)))

    def test_static_text_and_attributes_are_localized_without_changing_javascript(self):
        source = (
            '<button title="Chiudi" value="offro">🟢 Offro</button>'
            '<script>alert("Seleziona un comune dall’elenco.")</script>'
        )
        localized = localize_html_document(source, "en")

        self.assertIn('title="Close"', localized)
        self.assertIn('value="offro"', localized)
        self.assertIn("🟢 I offer", localized)
        self.assertIn('alert("Seleziona un comune dall’elenco.")', localized)

    def test_runtime_translation_can_localize_javascript_messages(self):
        self.assertEqual(translate_source("Mi interessa", "en"), "I’m interested")

    def test_dynamic_count_patterns_are_localized(self):
        self.assertEqual(translate_source("3 recensioni", "en"), "3 reviews")
        self.assertEqual(translate_source("Pagina 2 di 8", "fr"), "Page 2 sur 8")
        self.assertEqual(
            translate_source("Foto profilo di @MARIO", "de"),
            "Profilfoto von @MARIO",
        )
        self.assertEqual(
            translate_source("Babysitter - Offro - Milano", "es"),
            "Canguro - Ofrezco - Milano",
        )

    def test_frontend_catalogs_are_available_for_dynamic_content(self):
        self.assertEqual(frontend_source_catalog("it"), {})
        self.assertTrue(frontend_source_catalog("es"))
        self.assertTrue(frontend_pattern_catalog("de"))


if __name__ == "__main__":
    unittest.main()
