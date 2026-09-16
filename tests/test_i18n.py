import unittest
from pathlib import Path

from i18n import (
    EXTRA_LANGUAGE_ORDER,
    EXTRA_PATTERN_TRANSLATIONS,
    EXTRA_SOURCE_TRANSLATIONS,
    LEGAL_SOURCE_TRANSLATIONS,
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
        for key, variants in TRANSLATIONS.items():
            for language in SUPPORTED_LANGUAGES:
                self.assertTrue(
                    translate(key, language).strip(),
                    f"Traduzione vuota per {key} in {language}",
                )

    def test_extra_language_catalogs_are_complete(self):
        expected = set(EXTRA_LANGUAGE_ORDER)
        self.assertGreaterEqual(len(EXTRA_SOURCE_TRANSLATIONS), 1300)
        self.assertGreaterEqual(len(EXTRA_PATTERN_TRANSLATIONS), 50)

        for source, variants in EXTRA_SOURCE_TRANSLATIONS.items():
            self.assertEqual(set(variants), expected, source)
        for pattern, variants in EXTRA_PATTERN_TRANSLATIONS.items():
            self.assertEqual(set(variants), expected, pattern)

    def test_language_codes_are_normalized(self):
        self.assertEqual(normalize_language("en-US"), "en")
        self.assertEqual(normalize_language("FR_fr"), "fr")
        self.assertEqual(normalize_language("uk-UA"), "uk")
        self.assertEqual(normalize_language("fil-PH"), "fil")
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
        for language in EXTRA_LANGUAGE_ORDER:
            self.assertTrue(frontend_source_catalog(language))
            self.assertTrue(frontend_pattern_catalog(language))

    def test_legal_documents_have_complete_server_side_translations(self):
        expected = set(SUPPORTED_LANGUAGES)
        self.assertGreaterEqual(len(LEGAL_SOURCE_TRANSLATIONS), 160)

        for source, variants in LEGAL_SOURCE_TRANSLATIONS.items():
            self.assertEqual(set(variants), expected, source)

        privacy_source = (
            "La presente informativa descrive come MyLocalCare raccoglie, utilizza e "
            "protegge i dati personali degli utenti che si registrano e utilizzano la piattaforma."
        )
        self.assertNotEqual(translate_source(privacy_source, "en"), privacy_source)
        self.assertNotIn(privacy_source, frontend_source_catalog("en"))

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

    def test_language_controls_are_compact_flag_buttons(self):
        for template_name in ("home.html", "landing.html", "register.html"):
            source = (self.ROOT / "templates" / template_name).read_text(encoding="utf-8")
            self.assertIn("data-language-open", source)
            self.assertNotIn("<span>{{ tr('language.open') }}</span>", source)

        home = (self.ROOT / "templates" / "home.html").read_text(encoding="utf-8")
        register = (self.ROOT / "templates" / "register.html").read_text(encoding="utf-8")
        self.assertNotIn("home-language-code", home)
        self.assertNotIn("{{ current_language.short }}", register)

    def test_legal_pages_offer_language_switching(self):
        for template_name in ("privacy.html", "termini.html", "cookie_policy.html"):
            source = (self.ROOT / "templates" / template_name).read_text(encoding="utf-8")
            self.assertIn("partials/legal_language_control.html", source)

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
            self.assertIn("aggiornaRiepilogoVisibilita(loadToken)", source)
            self.assertIn("box.dataset.visibilityLoading", source)
            self.assertIn("}, 4000);", source)

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
