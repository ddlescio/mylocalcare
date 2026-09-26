import re
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"


class DisponibilitaServiziUiTest(unittest.TestCase):
    def read_template(self, relative_path):
        return (TEMPLATES / relative_path).read_text(encoding="utf-8")

    def test_display_partial_compiles_and_exposes_expected_macros(self):
        environment = Environment(loader=FileSystemLoader(str(TEMPLATES)))
        environment.filters.update(
            {
                "fmt_day_month": lambda value: value,
                "fmt_it_date": lambda value: value,
                "datetimeformat": lambda value: value,
            }
        )
        template = environment.get_template(
            "partials/disponibilita_servizi_display.html"
        )
        module = template.make_module(
            {
                "tr": lambda key, **kwargs: key,
            }
        )

        self.assertTrue(callable(module.availability_badge))
        self.assertTrue(callable(module.availability_intro))
        self.assertTrue(callable(module.availability_listing))

    def test_availability_was_removed_from_both_info_tabs(self):
        for template_name in (
            "partials/tab_info_privato.html",
            "partials/tab_info_pubblico.html",
        ):
            with self.subTest(template=template_name):
                source = self.read_template(template_name)
                self.assertNotIn("service-availability-card", source)
                self.assertNotIn("disponibilita_servizi_", source)
                self.assertNotIn("availability.title", source)

    def test_compact_availability_is_immediately_below_profile_phrase(self):
        dashboard = self.read_template("dashboard.html")

        phrase_start = dashboard.index('id="intro-info-base"')
        availability_start = dashboard.index("{{ availability_intro(")
        activities_start = dashboard.index("<!-- 🔹 Attività Offro / Cerco -->")

        self.assertLess(phrase_start, availability_start)
        self.assertLess(availability_start, activities_start)
        self.assertIn(
            "tr('availability.view') if pubblico else tr('availability.edit')",
            self.read_template("partials/disponibilita_servizi_display.html"),
        )
        self.assertIn("utente_offre_servizi=utente_offre_servizi|default(false)", dashboard)

    def test_badges_distinguish_state_and_freshness(self):
        source = self.read_template("partials/disponibilita_servizi_display.html")
        for css_class in (
            "is-available", "is-limited", "is-unavailable",
            "is-expired", "is-never-confirmed",
        ):
            self.assertIn(css_class, source)
        for key in (
            "availability.card_available_on", "availability.card_limited_on",
            "availability.card_unavailable_on", "availability.card_expired",
            "availability.card_never_confirmed",
        ):
            self.assertIn(key, source)

    def test_unavailable_state_does_not_show_schedule_sections(self):
        source = self.read_template("partials/disponibilita_servizi_display.html")
        self.assertIn("availability.unavailable_details", source)
        self.assertIn(
            "disponibilita.get('stato') != 'non_disponibile' and disponibilita.get('date_speciali')",
            source,
        )
        self.assertIn(
            "disponibilita.get('stato') != 'non_disponibile' and disponibilita.get('assenze')",
            source,
        )

    def test_public_offer_without_profile_shows_availability_to_confirm(self):
        source = self.read_template("partials/disponibilita_servizi_display.html")
        self.assertIn(
            "utente_offre_servizi or ((not pubblico) and profili)",
            source,
        )
        self.assertIn("feature_available and mostra_disponibilita", source)
        self.assertIn("availability_badge(none", source)

    def test_private_orphan_profile_remains_manageable(self):
        source = self.read_template("partials/disponibilita_servizi_display.html")
        self.assertIn("((not pubblico) and profili)", source)
        self.assertIn("data-service-availability-open", source)
        self.assertIn("data-service-availability-reconfirm", source)

    def test_search_badge_is_present_in_all_three_cards_and_only_for_offers(self):
        search = self.read_template("cerca.html")

        self.assertEqual(search.count("{{ availability_badge("), 3)
        guarded_badges = re.findall(
            r"\{% if a\.get\('tipo_annuncio'\) == 'offro' %\}"
            r"(?:(?!\{% endif %\}).)*?\{\{ availability_badge\(",
            search,
            flags=re.DOTALL,
        )
        self.assertEqual(len(guarded_badges), 3)

    def test_search_exposes_confirmed_availability_filter_in_both_controls(self):
        search = self.read_template("cerca.html")

        self.assertIn('name="solo_disponibili"', search)
        self.assertIn('id="solo-disponibili-rapido"', search)
        self.assertEqual(search.count("tr('search.available_only')"), 2)
        self.assertIn('url.searchParams.set("solo_disponibili", "1")', search)
        self.assertIn('url.searchParams.delete("solo_disponibili")', search)

    def test_profile_listing_badge_is_only_rendered_for_offers(self):
        dashboard = self.read_template("dashboard.html")

        self.assertEqual(dashboard.count("{{ availability_badge("), 1)
        self.assertRegex(
            dashboard,
            re.compile(
                r"\{% if a\.get\('tipo_annuncio'\) == 'offro' %\}"
                r"(?:(?!\{% endif %\}).)*?\{\{ availability_badge\(",
                flags=re.DOTALL,
            ),
        )

    def test_public_listing_has_expandable_details_only_for_offers(self):
        listing = self.read_template("annuncio_pubblico.html")
        display = self.read_template("partials/disponibilita_servizi_display.html")

        self.assertIn(
            "{% from \"partials/disponibilita_servizi_display.html\" import "
            "availability_listing with context %}",
            listing,
        )
        self.assertRegex(
            listing,
            re.compile(
                r"\{% if annuncio\.get\('tipo_annuncio'\) == 'offro' %\}"
                r"\s*\{\{ availability_listing\("
                r"\s*disponibilita_annuncio\|default\(None\),"
                r"\s*can_request=puo_richiedere_disponibilita"
                r"\s*\) \}\}"
                r"\s*\{% endif %\}",
                flags=re.DOTALL,
            ),
        )
        self.assertIn('<details class="availability-listing-details">', display)
        self.assertIn("{{ availability_details(disponibilita) }}", display)

    def test_new_display_components_have_mobile_first_styles(self):
        css = (
            ROOT / "static" / "css" / "disponibilita-servizi-display.css"
        ).read_text(encoding="utf-8")

        for selector in (
            ".availability-card-badge",
            ".intro-availability",
            ".availability-listing-details",
            ".profile-annuncio-availability",
            ".card-availability-row",
            ".vetrina-availability-row",
        ):
            with self.subTest(selector=selector):
                self.assertIn(selector, css)
        self.assertIn("@media (max-width: 420px)", css)


if __name__ == "__main__":
    unittest.main()
