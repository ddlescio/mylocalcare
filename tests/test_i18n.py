import unittest
from pathlib import Path

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
    ROOT = Path(__file__).resolve().parents[1]

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
        self.assertEqual(
            translate_source(
                "Impossibile caricare lo stato dei servizi. Riprova tra poco.",
                "en",
            ),
            "Unable to load the service status. Please try again shortly.",
        )

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

    def test_language_selector_is_visible_on_both_public_entry_pages(self):
        landing = (self.ROOT / "templates" / "landing.html").read_text(encoding="utf-8")
        home = (self.ROOT / "templates" / "home.html").read_text(encoding="utf-8")

        self.assertIn("data-language-open", landing)
        self.assertNotIn("absolute top-4 right-4", landing)
        self.assertIn("data-language-open", home)
        self.assertIn('partials/language_selector.html', home)

    def test_registration_has_language_selector_and_explicit_legal_translations(self):
        register = (self.ROOT / "templates" / "register.html").read_text(encoding="utf-8")

        self.assertIn("data-language-open", register)
        self.assertIn("partials/language_selector.html", register)
        self.assertIn("register.consent_intro", register)
        self.assertIn("register.privacy", register)
        self.assertIn("register.cookie", register)
        self.assertIn("register.terms", register)
        self.assertIn("REGISTER_COPY.emailConfirmationWarning", register)

    def test_private_gallery_warnings_use_complete_translation_keys(self):
        gallery = (self.ROOT / "templates" / "partials" / "tab_foto_privato.html").read_text(encoding="utf-8")

        self.assertIn("gallery.no_contacts_body", gallery)
        self.assertIn("gallery.review_notice", gallery)
        self.assertIn("gallery.uploading", gallery)
        self.assertIn("gallery.limit_reached", gallery)
        self.assertNotIn("Le foto della galleria servono per presentarti meglio, ma non devono contenere\n", gallery)

    def test_registration_backend_email_warnings_are_localized(self):
        warning = (
            "Controlla l’indirizzo email: hai scritto prova@gmai.com. "
            "Forse intendevi prova@gmail.com? "
            "Se l’email è sbagliata non riceverai il link di conferma."
        )
        translated = translate_source(warning, "en")

        self.assertIn("Check the email address", translated)
        self.assertIn("prova@gmai.com", translated)
        self.assertIn("prova@gmail.com", translated)

    def test_visibility_loader_is_bounded_and_language_safe(self):
        for template_name in ("dashboard.html", "annuncio_pubblico.html"):
            source = (self.ROOT / "templates" / template_name).read_text(encoding="utf-8")
            self.assertIn("Promise.allSettled", source)
            self.assertIn("VISIBILITA_LOAD_TOKEN", source)
            self.assertIn("controller.abort(), 8000", source)
            self.assertIn("mostraErroreStatoVisibilita", source)

    def test_profile_photo_viewers_have_visible_close_controls(self):
        dashboard = (self.ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        listing = (self.ROOT / "templates" / "annuncio_pubblico.html").read_text(encoding="utf-8")

        self.assertIn('id="chiudiModaleFoto"', dashboard)
        self.assertIn("<span>Chiudi</span>", dashboard)
        self.assertIn('data-profile-photo-stage', dashboard)
        self.assertIn('id="zoom-close"', listing)
        self.assertIn('class="zoom-close-label">Chiudi</span>', listing)


if __name__ == "__main__":
    unittest.main()
