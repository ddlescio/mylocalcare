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

    def test_search_exposes_confirmed_availability_only_inside_panel(self):
        search = self.read_template("cerca.html")

        self.assertIn('name="solo_disponibili"', search)
        self.assertNotIn('id="solo-disponibili-rapido"', search)
        self.assertEqual(search.count("tr('search.available_only')"), 1)
        self.assertNotIn('url.searchParams.set("solo_disponibili", "1")', search)
        self.assertIn('"solo_disponibili",', search)

    def test_search_header_has_only_primary_filter_actions(self):
        search = self.read_template("cerca.html")

        header_start = search.index('class="header-cerca')
        header_end = search.index("<!-- 🎯 Filtri attivi -->")
        header = search[header_start:header_end]
        self.assertIn('id="toggle-filtri"', header)
        self.assertIn('id="reset-filtri"', header)
        self.assertIn('id="includi-confinanti-rapido"', header)
        self.assertNotIn('id="solo-disponibili-rapido"', header)
        self.assertNotIn('id="solo-interessi-rapido"', header)

    def test_search_panel_has_top_apply_before_close(self):
        search = self.read_template("cerca.html")

        self.assertLess(search.index('id="apply-filtri-top"'), search.index('id="close-filtri"'))
        self.assertGreaterEqual(search.count('type="submit"'), 2)

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

    def test_public_listing_distinguishes_offered_and_sought_availability(self):
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
                r"\s*\{% elif annuncio\.get\('tipo_annuncio'\) == 'cerco' %\}"
                r"\s*\{\{ sought_availability_listing\("
                r"disponibilita_annuncio\|default\(None\)\) \}\}"
                r"\s*\{% endif %\}",
                flags=re.DOTALL,
            ),
        )
        self.assertIn('<details class="availability-listing-details">', display)
        self.assertIn("{{ availability_details(disponibilita) }}", display)
        self.assertIn("{% macro sought_availability_listing", display)

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

    def test_provider_exact_time_inputs_allow_minute_precision(self):
        dialog = self.read_template(
            "partials/disponibilita_servizi_dialog.html"
        )

        self.assertIn('input.type = "time"', dialog)
        self.assertIn('input.step = "60"', dialog)
        self.assertNotIn('input.step = "900"', dialog)

    def test_unavailable_category_offers_single_listing_choice_after_save(self):
        dialog = self.read_template(
            "partials/disponibilita_servizi_dialog.html"
        )

        self.assertIn('id="service-availability-listing-choice"', dialog)
        self.assertIn('id="service-availability-listing-keep"', dialog)
        self.assertIn('id="service-availability-listing-delete"', dialog)
        self.assertIn("payload.categoria_slug", dialog)
        self.assertIn(
            'payload.disponibilita.stato === "non_disponibile"',
            dialog,
        )
        self.assertIn("apiData && apiData.annunci_attivi_categoria", dialog)

    def test_listing_deletion_is_individual_and_requires_title_confirmation(self):
        dialog = self.read_template(
            "partials/disponibilita_servizi_dialog.html"
        )

        self.assertIn("selectedListingForDeletion()", dialog)
        self.assertIn("{ title: listing.titolo }", dialog)
        self.assertIn("window.confirm(confirmation)", dialog)
        self.assertIn(
            "fetch(`/api/annunci/${listing.id}/elimina`",
            dialog,
        )
        self.assertIn('method: "DELETE"', dialog)
        self.assertIn('"X-CSRF-Token": csrfToken', dialog)

    def test_every_choice_exit_keeps_listing_and_refreshes_saved_state(self):
        dialog = self.read_template(
            "partials/disponibilita_servizi_dialog.html"
        )

        close_start = dialog.index("function closeDialog()")
        close_end = dialog.index("async function loadAvailability", close_start)
        close_body = dialog[close_start:close_end]
        self.assertIn("listingChoiceRequiresReload()", close_body)
        self.assertIn("window.location.reload()", close_body)
        self.assertLess(
            close_body.index("listingChoiceRequiresReload()"),
            close_body.index('dialog.classList.add("service-availability-hidden")'),
        )
        self.assertIn(
            'listingKeepButton.addEventListener("click", closeDialog)',
            dialog,
        )
        self.assertIn(
            'dialog.querySelectorAll("[data-service-availability-close]")',
            dialog,
        )
        self.assertIn('if (event.key === "Escape")', dialog)
        self.assertIn("closeDialog();", dialog)

    def test_listing_delete_api_checks_csrf_owner_and_active_state(self):
        app_source = (ROOT / "app.py").read_text(encoding="utf-8")
        start = app_source.index("def elimina_annuncio_api(id):")
        end = app_source.index("# --- Foto Profilo ---", start)
        route = app_source[start:end]

        self.assertIn("verify_csrf()", route)
        self.assertIn('int(annuncio["utente_id"]) != user_id', route)
        self.assertIn('annuncio["stato"]', route)
        self.assertIn("AND utente_id = ?", route)
        self.assertIn("AND stato = 'approvato'", route)
        self.assertIn("int(cur.rowcount or 0) != 1", route)


if __name__ == "__main__":
    unittest.main()
