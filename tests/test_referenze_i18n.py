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
            "reference.no_listing.title",
            "reference.no_listing.body",
            "reference.no_listing.action",
            "reference.response.processing_consent",
            "reference.response.contact_consent",
            "reference.response.public_consent",
            "reference.response.consents_title",
            "reference.response.consents_help",
            "reference.response.accept_all",
            "reference.response.incomplete_confirm",
            "reference.response.relationship_question",
            "reference.response.relationship_help",
            "reference.response.relationship.family",
            "reference.response.relationship.employer",
            "reference.response.relationship.client",
            "reference.response.relationship.organisation",
            "reference.response.relationship.other",
            "reference.invite.relationship_question",
            "reference.invite.relationship_help",
            "reference.response.comment_title",
            "reference.response.comment_help",
            "reference.response.phone_title",
            "reference.response.phone_label",
            "reference.response.phone_help",
            "reference.response.privacy_identity",
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

    def test_optional_phone_copy_explains_contact_scope_and_privacy(self):
        consent = translate("reference.response.contact_consent", "it")
        phone_help = translate("reference.response.phone_help", "it")
        privacy = translate("reference.response.privacy_identity", "it")

        self.assertNotIn("email", consent.casefold())
        self.assertIn("telefonicamente", consent)
        self.assertIn("Facoltativo", phone_help)
        self.assertIn("mai pubblico", phone_help)
        self.assertIn("più affidabile", phone_help)
        self.assertIn("seleziona anche l’autorizzazione", phone_help)
        self.assertIn("resteranno riservati", privacy)
        self.assertIn("profilo pubblico", privacy)

    def test_private_invitation_explainer_is_concise(self):
        body = translate("reference.how.body", "it")

        self.assertLessEqual(len(body.split()), 14)
        self.assertIn("link personale", body)
        self.assertIn("restano privati", body)
        self.assertNotIn("dopo la sua risposta", body.casefold())
        self.assertNotIn("mostrata sul tuo profilo", body.casefold())

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
            "Consenso al ricontatto telefonico e numero di telefono devono essere indicati insieme.",
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
