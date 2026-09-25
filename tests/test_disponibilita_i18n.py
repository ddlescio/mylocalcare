import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from i18n import SUPPORTED_LANGUAGES, TRANSLATIONS, translate


ROOT = Path(__file__).resolve().parents[1]


class DisponibilitaServiziTranslationsTest(unittest.TestCase):
    REQUIRED_KEYS = {
        "availability.title",
        "availability.private_subtitle",
        "availability.public_subtitle",
        "availability.setup",
        "availability.edit",
        "availability.reconfirm",
        "availability.reconfirmed",
        "availability.not_configured",
        "availability.unavailable_feature",
        "availability.overall_status",
        "availability.status_available",
        "availability.status_available_description",
        "availability.status_limited",
        "availability.status_limited_description",
        "availability.status_unavailable",
        "availability.status_unavailable_description",
        "availability.weekly_title",
        "availability.weekly_help",
        "availability.slot_morning",
        "availability.slot_afternoon",
        "availability.slot_evening",
        "availability.slot_night",
        "availability.day_monday",
        "availability.day_tuesday",
        "availability.day_wednesday",
        "availability.day_thursday",
        "availability.day_friday",
        "availability.day_saturday",
        "availability.day_sunday",
        "availability.day_monday_short",
        "availability.day_tuesday_short",
        "availability.day_wednesday_short",
        "availability.day_thursday_short",
        "availability.day_friday_short",
        "availability.day_saturday_short",
        "availability.day_sunday_short",
        "availability.special_title",
        "availability.special_help",
        "availability.add_special",
        "availability.special_available",
        "availability.special_unavailable",
        "availability.date",
        "availability.remove",
        "availability.absences_title",
        "availability.absences_help",
        "availability.add_absence",
        "availability.start",
        "availability.end",
        "availability.save",
        "availability.saving",
        "availability.saved",
        "availability.close",
        "availability.error_generic",
        "availability.error_select_slot",
        "availability.freshness_current",
        "availability.freshness_due",
        "availability.freshness_old",
        "availability.public_confirmed",
        "availability.applies_all_services",
        "availability.no_weekly",
        "availability.weekly_slots",
        "availability.view_schedule",
        "availability.exceptions_count",
        "availability.absences_count",
        "availability.add_special_date",
        "availability.cancel",
        "availability.confirm",
        "availability.confirming",
        "availability.dialog_eyebrow",
        "availability.dialog_subtitle",
        "availability.dialog_title",
        "availability.empty_absences",
        "availability.empty_special_dates",
        "availability.error_date_order",
        "availability.error_date_required",
        "availability.error_duplicate_date",
        "availability.error_invalid_data",
        "availability.error_load",
        "availability.error_save",
        "availability.error_special_slots",
        "availability.from",
        "availability.loading",
        "availability.overall_help",
        "availability.slots",
        "availability.special_date",
        "availability.special_dates_help",
        "availability.special_dates_title",
        "availability.to",
        "availability.type",
        "availability.scope_all_services",
        "availability.card_unconfirmed",
        "availability.card_confirmed_on",
        "availability.card_available_on",
        "availability.card_limited_on",
        "availability.card_unavailable_on",
        "availability.card_expired",
        "availability.card_never_confirmed",
        "availability.unavailable_details",
        "availability.last_confirmed_full",
        "availability.edit_this_scope",
        "availability.configured_scopes",
        "availability.view",
        "availability.add_service_availability",
        "availability.listing_title",
        "availability.scope_title",
        "availability.scope_help",
        "availability.scope_general",
        "availability.scope_category",
        "availability.choose_category",
        "availability.no_offered_categories",
        "availability.only_offers_notice",
        "availability.scope_category_disabled",
        "availability.public_data_notice",
        "availability.delete_profile",
        "availability.delete_profile_confirm",
        "availability.deleting",
        "availability.deleted",
        "availability.delete_privacy_note",
        "availability.delete_profile_category_fallback",
        "availability.listing_description_placeholder",
        "availability.contact_preferences_title",
        "availability.contact_preferences_subtitle",
        "availability.contacts_sidebar_description",
    }

    def test_required_availability_copy_is_registered(self):
        self.assertTrue(self.REQUIRED_KEYS.issubset(TRANSLATIONS))

    def test_every_availability_key_has_all_supported_languages(self):
        expected_languages = set(SUPPORTED_LANGUAGES)
        availability_keys = {
            key for key in TRANSLATIONS if key.startswith("availability.")
        }

        self.assertTrue(availability_keys)
        for key in availability_keys:
            variants = TRANSLATIONS[key]
            self.assertEqual(set(variants), expected_languages, key)
            for language, text in variants.items():
                self.assertTrue(text.strip(), f"{key} has empty {language} copy")

    def test_copy_describes_service_availability_not_contact_hours(self):
        italian = translate("availability.private_subtitle", "it").lower()
        english = translate("availability.private_subtitle", "en").lower()

        self.assertIn("servizi", italian)
        self.assertNotIn("contatt", italian)
        self.assertIn("services", english)
        self.assertNotIn("contact", english)

    def test_count_summaries_keep_their_placeholder_in_every_language(self):
        count_keys = (
            "availability.weekly_slots",
            "availability.exceptions_count",
            "availability.absences_count",
            "availability.configured_scopes",
        )

        for key in count_keys:
            for language in SUPPORTED_LANGUAGES:
                self.assertIn("{count}", TRANSLATIONS[key][language], key)
                rendered = translate(key, language, count=3)
                self.assertIn("3", rendered)
                self.assertNotIn("{count}", rendered)

    def test_date_summaries_keep_their_placeholder_in_every_language(self):
        date_keys = (
            "availability.card_confirmed_on",
            "availability.card_available_on",
            "availability.card_limited_on",
            "availability.card_unavailable_on",
            "availability.last_confirmed_full",
        )

        for key in date_keys:
            for language in SUPPORTED_LANGUAGES:
                self.assertIn("{date}", TRANSLATIONS[key][language], key)
                rendered = translate(key, language, date="25/09/2026")
                self.assertIn("25/09/2026", rendered)
                self.assertNotIn("{date}", rendered)

    def test_service_category_labels_are_translated(self):
        slugs = (
            "operatori-benessere", "aiuto-in-casa", "ripetizioni",
            "babysitter", "pet-sitter", "caregiver", "escursioni-sport",
            "biglietti-spettacoli", "libri-scuola", "caffe-parole",
            "family-kids", "eventi-socialita", "spazi-sale",
        )
        for slug in slugs:
            key = f"availability.category.{slug}"
            self.assertIn(key, TRANSLATIONS)
            self.assertEqual(set(TRANSLATIONS[key]), set(SUPPORTED_LANGUAGES))

    def test_public_profile_does_not_emit_private_availability_controls(self):
        environment = Environment(
            loader=FileSystemLoader(ROOT / "templates")
        )
        template = environment.get_template(
            "partials/disponibilita_servizi_dialog.html"
        )
        rendered = template.render(
            pubblico=True,
            tr=lambda key, **values: key,
            csrf_token=lambda: "private-token",
        )

        self.assertIn(".service-availability-card", rendered)
        self.assertNotIn('<script>', rendered)
        self.assertNotIn('id="service-availability-dialog"', rendered)
        self.assertNotIn("private-token", rendered)

    def test_private_profile_emits_dialog_and_csrf_protected_script(self):
        environment = Environment(
            loader=FileSystemLoader(ROOT / "templates")
        )
        template = environment.get_template(
            "partials/disponibilita_servizi_dialog.html"
        )
        rendered = template.render(
            pubblico=False,
            tr=lambda key, **values: key,
            csrf_token=lambda: "private-token",
        )

        self.assertIn('id="service-availability-dialog"', rendered)
        self.assertIn("private-token", rendered)
        self.assertIn('X-CSRF-Token', rendered)
        self.assertIn('/api/utente/disponibilita', rendered)


if __name__ == "__main__":
    unittest.main()
