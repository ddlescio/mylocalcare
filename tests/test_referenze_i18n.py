import unittest
from pathlib import Path

from i18n import SUPPORTED_LANGUAGES, translate, translate_source
from i18n_references import REFERENCE_TRANSLATIONS


class ReferenceTranslationsTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_every_reference_key_covers_all_supported_languages(self):
        expected = set(SUPPORTED_LANGUAGES)
        self.assertGreaterEqual(len(REFERENCE_TRANSLATIONS), 140)
        for key, translations in REFERENCE_TRANSLATIONS.items():
            self.assertEqual(set(translations), expected, key)
            for language, value in translations.items():
                self.assertTrue(value.strip(), f"{key}: {language}")

    def test_core_reference_copy_is_translated_in_every_non_italian_language(self):
        keys = (
            "reference.manager.title",
            "reference.manager.existing_only",
            "reference.response.processing_consent",
            "reference.result.thanks",
            "reference.email.subject",
            "reference.email.action",
            "reference.show_on_profile",
            "reference.hide_from_profile",
            "reference.manage_or_invite",
            "reference.public.view",
        )
        for key in keys:
            italian = translate(key, "it")
            for language in set(SUPPORTED_LANGUAGES) - {"it"}:
                self.assertNotEqual(translate(key, language), italian, (key, language))

    def test_email_and_notification_placeholders_are_formatted(self):
        for language in SUPPORTED_LANGUAGES:
            greeting = translate(
                "reference.email.greeting", language, name="Maria Rossi"
            )
            request = translate(
                "reference.email.request", language, username="@MARIO"
            )
            checked = translate(
                "reference.notification.checked", language, category="Babysitter"
            )
            self.assertIn("Maria Rossi", greeting)
            self.assertIn("@MARIO", request)
            self.assertIn("Babysitter", checked)
            self.assertNotIn("{name}", greeting)
            self.assertNotIn("{username}", request)
            self.assertNotIn("{category}", checked)

    def test_backend_labels_and_validation_errors_have_source_translations(self):
        sources = (
            "Oltre 2 anni",
            "Struttura",
            "Indica esplicitamente se hai avuto un’esperienza diretta.",
            "La pubblicazione del testo richiede una referenza pubblicabile.",
            "Richiesta salvata, ma l’email non è partita. Puoi reinviarla.",
        )
        for source in sources:
            for language in set(SUPPORTED_LANGUAGES) - {"it"}:
                self.assertNotEqual(
                    translate_source(source, language), source, (source, language)
                )

    def test_external_response_page_has_language_switcher_and_keeps_user_copy_private(self):
        response = (
            self.ROOT / "templates" / "referenza_risposta.html"
        ).read_text(encoding="utf-8")
        public = (
            self.ROOT / "templates" / "partials" / "referenze_pubbliche.html"
        ).read_text(encoding="utf-8")
        self.assertIn('partials/legal_language_control.html', response)
        self.assertIn('data-no-translate>{{ referenza.get(\'messaggio_invito\') }}', response)
        self.assertIn('data-no-translate', public)
        self.assertIn("reference.response.processing_consent", response)

    def test_existing_references_remain_manageable_without_offered_services(self):
        dashboard = (self.ROOT / "templates" / "dashboard.html").read_text(
            encoding="utf-8"
        )
        private_info = (
            self.ROOT / "templates" / "partials" / "tab_info_privato.html"
        ).read_text(encoding="utf-8")
        dialog = (
            self.ROOT / "templates" / "partials" / "referenze_dialog.html"
        ).read_text(encoding="utf-8")

        self.assertIn("referenze_disponibili|default(false) and (not pubblico or feedback_references_count > 0)", dashboard)
        self.assertIn("{% include 'partials/referenze_dialog.html' %}", dashboard)
        self.assertNotIn("referenze_dialog.html", private_info)
        self.assertNotIn("referenze_pubbliche.html", private_info)
        self.assertIn("reference.manager.existing_only", dialog)
        self.assertIn("{% if categorie_elenco %}", dialog)
        self.assertIn('class="reference-invite"', dialog)

    def test_user_reference_api_messages_are_localized_server_side(self):
        app_source = (self.ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn("def _referenza_ui_message", app_source)
        self.assertIn(
            'session["lingua_interfaccia"] = normalize_language(requested_language)',
            app_source,
        )
        self.assertNotIn("reference.error.remove_name", REFERENCE_TRANSLATIONS)


if __name__ == "__main__":
    unittest.main()
