import unittest
from pathlib import Path

from i18n import (
    EXTRA_LANGUAGE_ORDER,
    EXTRA_PATTERN_TRANSLATIONS,
    EXTRA_SOURCE_TRANSLATIONS,
    LEGAL_DOCUMENT_VERSION,
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

    def test_visibility_loader_uses_one_bounded_summary_request(self):
        app_source = (self.ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn(
            '@app.route("/api/annunci/<int:annuncio_id>/servizi-stato")',
            app_source,
        )

        for template_name in ("dashboard.html", "annuncio_pubblico.html"):
            source = (self.ROOT / "templates" / template_name).read_text(encoding="utf-8")
            self.assertIn("/servizi-stato?t=", source)
            self.assertIn("VISIBILITA_LOAD_TOKEN", source)
            self.assertIn("controller.abort(), 6000", source)
            self.assertIn('headers: { "Accept": "application/json" }', source)
            self.assertIn("dataPrecaricata = undefined", source)
            self.assertIn("mostraErroreStatoVisibilita", source)
            self.assertIn("aggiornaRiepilogoVisibilita(loadToken)", source)
            self.assertIn("box.dataset.visibilityLoading", source)
            self.assertIn("window.mlcPauseDynamicTranslation", source)
            self.assertIn("translationRelease?.(", source)

    def test_dynamic_translator_does_not_observe_its_own_changes(self):
        source = (self.ROOT / "templates" / "base.html").read_text(encoding="utf-8")

        self.assertIn("observer.disconnect();", source)
        self.assertIn("observer.takeRecords();", source)
        self.assertIn("window.mlcPauseDynamicTranslation", source)
        self.assertIn("window.mlcTranslateTree = translateTree", source)

    def test_no_translate_blocks_are_preserved_server_side(self):
        source = (
            '<textarea data-no-translate placeholder="Accedi">Accedi</textarea>'
            '<p>Accedi</p>'
        )
        localized = localize_html_document(source, "en")
        self.assertIn(
            '<textarea data-no-translate placeholder="Accedi">Accedi</textarea>',
            localized,
        )
        self.assertIn("<p>Sign in</p>", localized)

    def test_italian_content_notes_are_present_on_editable_fields(self):
        profile = (
            self.ROOT / "templates" / "partials" / "tab_info_privato.html"
        ).read_text(encoding="utf-8")
        new_listing = (self.ROOT / "templates" / "nuovo_annuncio.html").read_text(
            encoding="utf-8"
        )
        edit_listing = (
            self.ROOT / "templates" / "modifica_annuncio.html"
        ).read_text(encoding="utf-8")

        self.assertGreaterEqual(profile.count("content.write_italian_profile_note"), 2)
        self.assertIn("content.write_italian_listing_note", new_listing)
        self.assertIn("content.write_italian_listing_note", edit_listing)
        self.assertIn("data-no-translate", profile)
        self.assertIn("data-no-translate", new_listing)
        self.assertIn("data-no-translate", edit_listing)

    def test_profile_photo_viewers_have_visible_close_controls(self):
        dashboard = (self.ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        listing = (self.ROOT / "templates" / "annuncio_pubblico.html").read_text(encoding="utf-8")

        self.assertIn('id="chiudiModaleFoto"', dashboard)
        self.assertIn("<span>Chiudi</span>", dashboard)
        self.assertIn('data-profile-photo-stage', dashboard)
        self.assertIn('id="zoom-close"', listing)
        self.assertIn('class="zoom-close-label">Chiudi</span>', listing)

    def test_visible_file_inputs_use_translated_custom_picker(self):
        base = (self.ROOT / "templates" / "base.html").read_text(encoding="utf-8")

        self.assertIn("mlc-file-picker-button", base)
        self.assertIn("upload.choose_file", base)
        self.assertIn("upload.choose_files", base)
        self.assertIn("upload.no_file", base)
        self.assertIn("upload.files_selected", base)
        self.assertIn("input.files", base)
        self.assertIn("input.click()", base)
        self.assertIn('input[type="file"]', base)
        self.assertIn('input.classList.contains("hidden")', base)

    def test_profile_card_copy_covers_every_supported_language(self):
        keys = {
            "profile_card.sheet",
            "profile_card.catalog_title",
            "profile_card.request_check",
            "profile_card.request_benefit",
            "profile_card.request_process",
            "profile_card.state_declared",
            "profile_card.state_document",
            "profile_card.state_feedback",
            "profile_card.state_unverifiable",
            "profile_card.unverifiable_help",
            "profile_card.saved_requested",
            "profile_card.error_save",
            "profile_card.error_delete",
            "profile_card.no_contacts_note",
            "profile_card.public_data_notice",
            "profile_card.public_preview",
            "profile_card.linked_card",
            "profile_card.view_details",
            "profile_card.error_contacts",
            "profile_card.error_certificate_limit",
            "profile_card.error_request_rate_limit",
            "profile_card.confirm_delete",
            "profile_card.error_checked",
            "profile_card.error_unverifiable",
            "profile_card.error_changed",
            "profile_card.error_expired",
            "profile_card.error_acknowledgement",
        }

        profile_card_keys = {
            key for key in TRANSLATIONS if key.startswith("profile_card.")
        }
        self.assertTrue(keys.issubset(profile_card_keys))
        for key in profile_card_keys:
            self.assertEqual(set(TRANSLATIONS[key]), set(SUPPORTED_LANGUAGES), key)

        self.assertEqual(
            translate("profile_card.state_document", "en"),
            "Document viewed by MyLocalCare",
        )
        benefit = translate("profile_card.request_benefit", "it")
        self.assertIn("profilo pubblico", benefit)
        self.assertIn("Dichiarato dall’utente", benefit)
        self.assertEqual(
            translate_source("Scheda non trovata.", "es"),
            "Ficha no encontrada.",
        )

    def test_profile_card_dynamic_ui_uses_localized_copy(self):
        dialog = (
            self.ROOT / "templates" / "partials" / "schede_profilo_dialog.html"
        ).read_text(encoding="utf-8")
        private = (
            self.ROOT / "templates" / "partials" / "tab_info_privato.html"
        ).read_text(encoding="utf-8")
        public = (
            self.ROOT / "templates" / "partials" / "tab_info_pubblico.html"
        ).read_text(encoding="utf-8")

        self.assertIn("const copy = Object.freeze", dialog)
        self.assertIn("tr('profile_card.saved_requested')", dialog)
        self.assertIn("localizeApiError", dialog)
        self.assertIn("copy.errorChecked", dialog)
        self.assertIn("copy.errorChanged", dialog)
        self.assertIn("copy.errorExpired", dialog)
        self.assertIn("copy.errorContacts", dialog)
        self.assertIn("copy.errorCertificateLimit", dialog)
        self.assertIn("copy.errorRequestRateLimit", dialog)
        self.assertIn("massimo\\s+20\\s+certificazioni", dialog)
        self.assertIn("troppe\\s+richieste.*controllo", dialog)
        self.assertIn("tr('profile_card.no_contacts_note')", dialog)
        self.assertIn("tr('profile_card.request_benefit')", dialog)
        self.assertIn("tr('profile_card.request_process')", dialog)
        self.assertIn("tr('profile_card.state_unverifiable')", dialog)
        self.assertIn("profile-card-contact-note", dialog)
        self.assertIn("saveButton.textContent = copy.saving", dialog)
        self.assertIn("deleteButton.textContent = copy.deleting", dialog)
        self.assertIn('option.setAttribute("data-no-translate", "")', dialog)
        self.assertIn("data-profile-card-slot-preview", private)
        self.assertIn("data-profile-card-slot-input", private)
        self.assertIn("data-profile-card-slot-launcher", private)
        self.assertIn("tr('profile_card.linked_card')", private)
        self.assertIn("tr('profile_card.public_preview')", private)
        self.assertNotIn('saveButton.textContent = "Salva scheda"', dialog)
        self.assertNotIn('deleteButton.textContent = "Elimina scheda"', dialog)

        self.assertIn("tr('profile_card.short')", private)
        self.assertIn("tr('profile_card.add')", private)
        self.assertIn("tr('profile_card.state_document')", public)
        self.assertIn("tr('profile_card.state_feedback')", public)
        self.assertIn("tr('profile_card.state_declared')", public)
        self.assertIn("tr('profile_card.view_details')", public)
        self.assertIn("info-chip-profile-card-action", public)

    def test_profile_card_catalog_remains_complete_after_selection(self):
        dialog = (
            self.ROOT / "templates" / "partials" / "schede_profilo_dialog.html"
        ).read_text(encoding="utf-8")
        start = dialog.index("function populateCatalog")
        end = dialog.index("function syncCatalogTitle")
        populate = dialog[start:end]

        self.assertIn('String(entry.tipo_scheda || "") === type', populate)
        self.assertNotIn("allowedCategories", populate)
        self.assertNotIn("categoryInput.value", populate)
        self.assertNotIn("populateCatalog(activeCardType, entry.id", dialog)

    def test_profile_card_notice_and_legal_update_are_versioned(self):
        app_source = (self.ROOT / "app.py").read_text(encoding="utf-8")
        module_source = (self.ROOT / "profilo_schede.py").read_text(
            encoding="utf-8"
        )
        dialog = (
            self.ROOT / "templates" / "partials" / "schede_profilo_dialog.html"
        ).read_text(encoding="utf-8")

        for key in (
            "legal.version_label",
            "legal.profile_cards_privacy_title",
            "legal.profile_cards_privacy_body",
            "legal.profile_cards_privacy_retention",
            "legal.profile_cards_terms_title",
            "legal.profile_cards_terms_body",
            "legal.profile_cards_terms_duty",
        ):
            self.assertIn(key, TRANSLATIONS)
            self.assertEqual(
                set(TRANSLATIONS[key]), set(SUPPORTED_LANGUAGES), key
            )

        self.assertIn(
            'PROFILE_CARD_NOTICE_VERSION = "profile_cards_2026_v2"',
            module_source,
        )
        self.assertIn("acknowledged: true", dialog)
        self.assertIn('notice_version: "profile_cards_2026_v2"', dialog)
        self.assertEqual(
            LEGAL_DOCUMENT_VERSION,
            "mylocalcare_privacy_termini_2026_v2",
        )
        self.assertIn("LEGAL_DOCUMENT_VERSION", app_source)

        for template_name in (
            "privacy.html",
            "termini.html",
            "cookie_policy.html",
        ):
            source = (self.ROOT / "templates" / template_name).read_text(
                encoding="utf-8"
            )
            self.assertIn("{{ legal_document_version }}", source)

        privacy = (self.ROOT / "templates" / "privacy.html").read_text(
            encoding="utf-8"
        )
        terms = (self.ROOT / "templates" / "termini.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("legal.profile_cards_privacy_body", privacy)
        self.assertIn("legal.profile_cards_terms_body", terms)

    def test_video_age_confirmation_does_not_overwrite_legal_version(self):
        app_source = (self.ROOT / "app.py").read_text(encoding="utf-8")
        start = app_source.index(
            '@app.route("/video/verifica-maggiorenne", methods=["POST"])'
        )
        end = app_source.index(
            '@app.route("/video/check-maggiorenne")', start
        )
        route_source = app_source[start:end]

        self.assertNotIn("versione_consenso", route_source)
        self.assertNotIn("v1.0_video", route_source)

    def test_profile_card_mutations_send_version_and_use_independent_rate_limit(self):
        app_source = (self.ROOT / "app.py").read_text(encoding="utf-8")
        dialog = (
            self.ROOT / "templates" / "partials" / "schede_profilo_dialog.html"
        ).read_text(encoding="utf-8")

        self.assertIn("normalized.versione = Number", dialog)
        self.assertGreaterEqual(dialog.count("versione: Number"), 2)
        self.assertIn('"Content-Type": "application/json"', dialog)
        self.assertIn("versione_visualizzata", app_source)
        self.assertIn("_prenota_richiesta_controllo_scheda", app_source)
        self.assertIn("rate:profile-card-check:", app_source)
        self.assertIn("redis_client.eval", app_source)

    def test_screenshot_translation_gaps_use_explicit_keys(self):
        home = (self.ROOT / "templates" / "home.html").read_text(encoding="utf-8")
        dashboard = (self.ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        private_reviews = (
            self.ROOT / "templates" / "partials" / "tab_recensioni_privato.html"
        ).read_text(encoding="utf-8")
        public_reviews = (
            self.ROOT / "templates" / "partials" / "tab_recensioni_pubblico.html"
        ).read_text(encoding="utf-8")

        for key in (
            "home.category.babysitter_description",
            "home.category.home_help_description",
            "home.category.pet_sitter_description",
            "home.category.caregiver_description",
            "home.category.tutoring_description",
            "home.category.family_description",
        ):
            self.assertIn(key, home)

        self.assertIn("dashboard.empty_listings_body", dashboard)
        self.assertIn("reviews.private_intro", private_reviews)
        self.assertIn("reviews.private_summary", private_reviews)
        self.assertIn("reviews.manage_body", private_reviews)
        self.assertIn("reviews.empty_body", private_reviews)
        self.assertIn("reviews.public_none", public_reviews)
        self.assertIn("reviews.public_empty_body", public_reviews)


if __name__ == "__main__":
    unittest.main()
