import re
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"


class DisponibilitaServiziUiTest(unittest.TestCase):
    def read_template(self, relative_path):
        return (TEMPLATES / relative_path).read_text(encoding="utf-8")

    def render_availability_intro(self, profiles, *, public=False, offers=True):
        environment = Environment(loader=FileSystemLoader(str(TEMPLATES)))
        environment.filters.update(
            {
                "fmt_day_month": lambda value: value or "",
                "fmt_it_date": lambda value: value or "",
                "datetimeformat": lambda value: value or "",
            }
        )
        template = environment.get_template(
            "partials/disponibilita_servizi_display.html"
        )
        module = template.make_module(
            {"tr": lambda key, **kwargs: key}
        )
        return str(module.availability_intro(
            profiles,
            pubblico=public,
            feature_available=True,
            utente_offre_servizi=offers,
        ))

    def render_sought_availability_badge(self, availability, translator=None):
        environment = Environment(loader=FileSystemLoader(str(TEMPLATES)))
        environment.filters.update(
            {
                "fmt_day_month": lambda value: value or "",
                "fmt_it_date": lambda value: value or "",
                "datetimeformat": lambda value: value or "",
            }
        )
        template = environment.get_template(
            "partials/disponibilita_servizi_display.html"
        )
        module = template.make_module(
            {"tr": translator or (lambda key, **kwargs: key)}
        )
        return str(module.sought_availability_badge(availability))

    def render_availability_badge(
        self,
        availability,
        *,
        show_schedule=False,
        translator=None,
    ):
        environment = Environment(loader=FileSystemLoader(str(TEMPLATES)))
        environment.filters.update(
            {
                "fmt_day_month": lambda value: value or "",
                "fmt_it_date": lambda value: value or "",
                "datetimeformat": lambda value: value or "",
            }
        )
        template = environment.get_template(
            "partials/disponibilita_servizi_display.html"
        )
        module = template.make_module(
            {"tr": translator or (lambda key, **kwargs: key)}
        )
        return str(module.availability_badge(
            availability,
            show_schedule=show_schedule,
        ))

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
        self.assertTrue(callable(module.sought_availability_badge))

    def test_sought_availability_card_shows_compact_schedule(self):
        rendered = self.render_sought_availability_badge({
            "a_chiamata": True,
            "settimanale": [
                {"giorno_settimana": 1, "fascia": "mattina"},
                {"giorno_settimana": 5, "fascia": "mattina"},
            ],
            "settimanale_intervalli": [
                {
                    "giorno_settimana": 1,
                    "ora_inizio": "09:30",
                    "ora_fine": "12:00",
                    "giorno_successivo": False,
                },
                {
                    "giorno_settimana": 5,
                    "ora_inizio": "09:30",
                    "ora_fine": "12:00",
                    "giorno_successivo": False,
                },
            ],
        })

        self.assertIn("listing.sought_availability_badge", rendered)
        self.assertIn('title="availability.day_monday"', rendered)
        self.assertIn('title="availability.day_friday"', rendered)
        self.assertIn("availability.slot_morning", rendered)
        self.assertIn("availability.on_call_label", rendered)
        self.assertEqual(rendered.count("09:30–12:00"), 1)
        self.assertEqual(rendered.count('data-sought-availability-day='), 7)
        self.assertIn(
            'data-sought-availability-day="1"\n                data-selected="true"',
            rendered,
        )
        self.assertIn(
            'data-sought-availability-day="5"\n                data-selected="true"',
            rendered,
        )
        self.assertIn(
            'data-sought-availability-day="2"\n                data-selected="false"',
            rendered,
        )
        self.assertEqual(rendered.count('data-selected="true"'), 2)
        self.assertIn('data-sought-availability-group="on-call"', rendered)
        self.assertIn('class="sought-availability-compact__week"', rendered)
        self.assertIn('class="sought-availability-compact__day-groups"', rendered)
        self.assertIn('data-availability-detail-days="1,5"', rendered)
        # Una sola configurazione comune resta compatta: i quadratini grandi
        # hanno gia indicato i giorni e non vengono duplicati sotto.
        self.assertNotIn('class="sought-availability-compact__group-days"', rendered)

    def test_sought_availability_card_always_shows_seven_days_without_overflow(self):
        rendered = self.render_sought_availability_badge({
            "a_chiamata": False,
            "settimanale": [
                {"giorno_settimana": day, "fascia": "mattina"}
                for day in range(1, 5)
            ],
            "settimanale_intervalli": [],
        })

        self.assertEqual(rendered.count('data-sought-availability-day='), 7)
        self.assertEqual(rendered.count('data-selected="true"'), 4)
        self.assertEqual(rendered.count('data-selected="false"'), 3)
        self.assertEqual(rendered.count("availability.slot_morning"), 1)
        self.assertNotIn("sought-availability-compact__more", rendered)

    def test_sought_availability_card_uses_compact_italian_day_initials(self):
        translations = {
            "availability.day_monday": "Lunedì",
            "availability.day_tuesday": "Martedì",
            "availability.day_wednesday": "Mercoledì",
            "availability.day_thursday": "Giovedì",
            "availability.day_friday": "Venerdì",
            "availability.day_saturday": "Sabato",
            "availability.day_sunday": "Domenica",
        }
        rendered = self.render_sought_availability_badge(
            {
                "a_chiamata": False,
                "settimanale": [
                    {"giorno_settimana": 1, "fascia": "mattina"},
                    {"giorno_settimana": 3, "fascia": "mattina"},
                ],
                "settimanale_intervalli": [],
            },
            translator=lambda key, **kwargs: translations.get(key, key),
        )

        initials = re.findall(
            r'sought-availability-compact__day[^>]*>\s*'
            r'<span aria-hidden="true">([^<]+)</span>',
            rendered,
        )
        self.assertEqual(initials, ["L", "M", "M", "G", "V", "S", "D"])
        self.assertEqual(rendered.count('data-selected="true"'), 2)

    def test_sought_card_preserves_different_times_per_day(self):
        translations = {
            "availability.day_tuesday": "Martedì",
            "availability.day_wednesday": "Mercoledì",
            "availability.day_tuesday_short": "Mar",
            "availability.day_wednesday_short": "Mer",
        }
        rendered = self.render_sought_availability_badge(
            {
                "a_chiamata": False,
                "settimanale": [],
                "settimanale_intervalli": [
                    {
                        "giorno_settimana": 2,
                        "ora_inizio": "09:00",
                        "ora_fine": "12:00",
                        "giorno_successivo": False,
                    },
                    {
                        "giorno_settimana": 3,
                        "ora_inizio": "14:00",
                        "ora_fine": "18:00",
                        "giorno_successivo": False,
                    },
                ],
            },
            translator=lambda key, **kwargs: translations.get(key, key),
        )

        tuesday = rendered.index('data-availability-detail-days="2"')
        tuesday_label = rendered.index(">Mar</span>", tuesday)
        tuesday_time = rendered.index("09:00–12:00")
        wednesday = rendered.index('data-availability-detail-days="3"')
        wednesday_label = rendered.index(">Mer</span>", wednesday)
        wednesday_time = rendered.index("14:00–18:00")
        self.assertLess(tuesday, tuesday_label)
        self.assertLess(tuesday_label, tuesday_time)
        self.assertLess(tuesday_time, wednesday)
        self.assertLess(wednesday, wednesday_label)
        self.assertLess(wednesday_label, wednesday_time)
        self.assertIn('class="sought-availability-compact__group-days"', rendered)

    def test_offered_card_adds_same_compact_week_when_schedule_is_present(self):
        translations = {
            "availability.day_monday": "Lunedì",
            "availability.day_tuesday": "Martedì",
            "availability.day_wednesday": "Mercoledì",
            "availability.day_thursday": "Giovedì",
            "availability.day_friday": "Venerdì",
            "availability.day_saturday": "Sabato",
            "availability.day_sunday": "Domenica",
        }
        rendered = self.render_availability_badge(
            {
                "configurata": True,
                "stato": "disponibile",
                "a_chiamata": True,
                "confermata_at": "2026-10-02",
                "freschezza": {
                    "codice": "fresca",
                    "confermata_il": "2026-10-02",
                },
                "settimanale": [
                    {"giorno_settimana": 2, "fascia": "pomeriggio"},
                    {"giorno_settimana": 6, "fascia": "pomeriggio"},
                ],
                "settimanale_intervalli": [{
                    "giorno_settimana": 2,
                    "ora_inizio": "14:30",
                    "ora_fine": "18:00",
                    "giorno_successivo": False,
                }],
            },
            show_schedule=True,
            translator=lambda key, **kwargs: translations.get(key, key),
        )

        initials = re.findall(
            r'sought-availability-compact__day[^>]*>\s*'
            r'<span aria-hidden="true">([^<]+)</span>',
            rendered,
        )
        self.assertEqual(initials, ["L", "M", "M", "G", "V", "S", "D"])
        self.assertEqual(rendered.count('data-sought-availability-day='), 7)
        self.assertEqual(rendered.count('data-selected="true"'), 2)
        self.assertIn("availability.card_available_on", rendered)
        self.assertIn("availability.slot_afternoon", rendered)
        self.assertIn("14:30–18:00", rendered)
        self.assertIn("availability.on_call_label", rendered)
        self.assertIn("offered-availability-card", rendered)
        self.assertIn('data-availability-detail-days="2"', rendered)
        self.assertIn('data-availability-detail-days="6"', rendered)

        # L'orario preciso del martedi non deve essere presentato come se
        # valesse anche per il sabato, che condivide soltanto la fascia.
        tuesday_group = rendered.index('data-availability-detail-days="2"')
        saturday_group = rendered.index('data-availability-detail-days="6"')
        exact_time = rendered.index("14:30–18:00")
        self.assertLess(tuesday_group, exact_time)
        self.assertLess(exact_time, saturday_group)

    def test_offered_card_without_days_keeps_only_confirmation_badge(self):
        rendered = self.render_availability_badge(
            {
                "configurata": True,
                "stato": "disponibile",
                "a_chiamata": True,
                "confermata_at": "2026-10-02",
                "freschezza": {
                    "codice": "fresca",
                    "confermata_il": "2026-10-02",
                },
                "settimanale": [],
                "settimanale_intervalli": [],
            },
            show_schedule=True,
        )

        self.assertIn("availability.card_available_on", rendered)
        self.assertNotIn("offered-availability-card", rendered)
        self.assertNotIn("data-sought-availability-day=", rendered)
        self.assertNotIn("availability.on_call_label", rendered)

    def test_display_partial_does_not_nest_duplicate_items_wrappers(self):
        source = self.read_template("partials/disponibilita_servizi_display.html")

        self.assertNotRegex(
            source,
            re.compile(
                r'<div class="availability-detail__items">\s*'
                r'<div class="availability-detail__items">'
            ),
        )

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
            "availability.card_unavailable_reconfirmation",
            "availability.card_never_confirmed",
        ):
            self.assertIn(key, source)

    def test_system_expiry_badge_has_exact_label_without_old_date(self):
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
        translations = {
            "availability.card_unavailable_reconfirmation": (
                "Non disponibile · conferma richiesta"
            ),
        }
        module = template.make_module(
            {
                "tr": lambda key, **kwargs: translations.get(key, key),
            }
        )

        badge = str(module.availability_badge({
            "configurata": True,
            "stato": "non_disponibile",
            "non_disponibile_per_scadenza": True,
            "confermata_at": "2026-08-01",
            "freschezza": {
                "codice": "priorita_ridotta",
                "riconferma_richiesta": True,
                "confermata_il": "2026-08-01",
            },
        }))

        self.assertIn("Non disponibile · conferma richiesta", badge)
        self.assertNotIn("2026-08-01", badge)
        self.assertNotIn("availability.card_expired", badge)

    def test_voluntary_unavailable_does_not_get_system_expiry_label(self):
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
        module = template.make_module({"tr": lambda key, **kwargs: key})

        badge = str(module.availability_badge({
            "configurata": True,
            "stato": "non_disponibile",
            "confermata_at": "2026-08-01",
            "freschezza": {
                "codice": "esclusa_filtro",
                "riconferma_richiesta": True,
                "confermata_il": "2026-08-01",
            },
        }))

        self.assertIn("availability.card_unavailable_on", badge)
        self.assertNotIn("availability.card_expired", badge)
        self.assertNotIn(
            "availability.card_unavailable_reconfirmation",
            badge,
        )

    def test_status_pickers_use_distinct_non_colour_symbols(self):
        templates = (
            (
                "partials/annuncio_disponibilita_picker.html",
                "listing-availability__status-dot",
            ),
            (
                "partials/disponibilita_servizi_dialog.html",
                "service-availability-status-dot",
            ),
        )
        for template_name, css_class in templates:
            source = self.read_template(template_name)
            with self.subTest(template=template_name):
                for symbol in ("✓", "◐", "×"):
                    self.assertIn(
                        f'class="{css_class}" aria-hidden="true">{symbol}</span>',
                        source,
                    )

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

    def test_private_unconfirmed_availability_gets_premium_attention(self):
        rendered = self.render_availability_intro([], public=False, offers=True)

        self.assertIn("intro-availability--needs-confirmation", rendered)
        self.assertIn('data-availability-needs-confirmation="true"', rendered)
        self.assertIn("availability.action_to_confirm", rendered)

    def test_private_reconfirmation_promotes_the_due_scope(self):
        fresh = {
            "configurata": True,
            "stato": "disponibile",
            "confermata_at": "2026-09-29",
            "categoria_slug": "babysitter",
            "freschezza": {"codice": "aggiornata"},
        }
        due = {
            "configurata": True,
            "stato": "limitata",
            "confermata_at": "2026-08-20",
            "categoria_slug": "pet-sitter",
            "freschezza": {
                "codice": "da_riconfermare",
                "riconferma_richiesta": True,
            },
        }

        rendered = self.render_availability_intro(
            [fresh, due], public=False, offers=True
        )

        self.assertIn("intro-availability--needs-confirmation", rendered)
        self.assertIn("availability.card_expired", rendered)
        self.assertLess(
            rendered.index("availability.card_expired"),
            rendered.index("availability.card_available_on"),
        )

    def test_fresh_and_voluntary_unavailable_cards_do_not_pulse(self):
        cases = (
            {
                "configurata": True,
                "stato": "disponibile",
                "confermata_at": "2026-09-29",
                "freschezza": {"codice": "aggiornata"},
            },
            {
                "configurata": True,
                "stato": "non_disponibile",
                "confermata_at": "2026-09-29",
                "freschezza": {
                    "codice": "esclusa_filtro",
                    "riconferma_richiesta": True,
                },
            },
        )

        for profile in cases:
            with self.subTest(state=profile["stato"]):
                rendered = self.render_availability_intro(
                    [profile], public=False, offers=True
                )
                self.assertNotIn(
                    "intro-availability--needs-confirmation", rendered
                )
                self.assertNotIn("availability.action_to_confirm", rendered)

    def test_public_profile_never_uses_private_confirmation_animation(self):
        profile = {
            "configurata": False,
            "stato": "non_disponibile",
            "freschezza": {"codice": "mai_confermata"},
        }
        rendered = self.render_availability_intro(
            [profile], public=True, offers=True
        )

        self.assertNotIn("intro-availability--needs-confirmation", rendered)
        self.assertNotIn("availability.action_to_confirm", rendered)

    def test_confirmation_animation_respects_reduced_motion(self):
        css = (
            ROOT / "static" / "css" / "disponibilita-servizi-display.css"
        ).read_text(encoding="utf-8")

        self.assertIn("@keyframes availability-confirmation-glow", css)
        self.assertIn("@keyframes availability-confirmation-sheen", css)
        self.assertIn("@keyframes availability-confirmation-sway", css)
        self.assertRegex(
            css,
            re.compile(
                r"\.intro-availability--needs-confirmation\s*\{.*?"
                r"border-color:\s*rgba\(99,\s*102,\s*241,\s*\.94\).*?"
                r"inset 0 0 0 1px rgba\(129,\s*140,\s*248,\s*\.18\).*?"
                r"availability-confirmation-sway",
                flags=re.DOTALL,
            ),
        )
        self.assertRegex(
            css,
            re.compile(
                r"@keyframes availability-confirmation-sway\s*\{.*?"
                r"transform:\s*translate3d\(",
                flags=re.DOTALL,
            ),
        )
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)
        self.assertRegex(
            css,
            re.compile(
                r"@media \(prefers-reduced-motion: reduce\).*?"
                r"\.intro-availability--needs-confirmation.*?animation: none",
                flags=re.DOTALL,
            ),
        )

    def test_dialog_exposes_real_confirm_all_action(self):
        source = self.read_template("partials/disponibilita_servizi_dialog.html")
        self.assertIn("data-service-availability-confirm-all", source)
        self.assertIn(
            'fetch(\n        "/api/utente/disponibilita/riconferma-tutte"',
            source,
        )
        self.assertIn("copy.confirmedAll", source)
        self.assertIn("copy.confirmedAllWithConflicts", source)
        self.assertIn("data.conflitti", source)

    def test_archived_listing_uses_one_click_reactivation(self):
        dashboard = self.read_template("dashboard.html")
        self.assertIn("data-service-availability-reactivate", dashboard)
        self.assertIn('data-annuncio-id="{{ a[\'id\'] }}"', dashboard)
        self.assertNotIn(
            "data-service-availability-open\n"
            "                          data-service-availability-category",
            dashboard,
        )
        dialog = self.read_template("partials/disponibilita_servizi_dialog.html")
        self.assertIn(
            "`/api/annunci/${listingId}/riattiva-disponibilita`",
            dialog,
        )
        self.assertIn('code === "duplicate_active_listing"', dialog)

    def test_search_badge_is_present_in_all_three_cards_and_only_for_offers(self):
        search = self.read_template("cerca.html")

        self.assertEqual(search.count("{{ availability_badge("), 3)
        self.assertEqual(search.count("show_schedule=true"), 3)
        guarded_badges = re.findall(
            r"\{% if a\.get\('tipo_annuncio'\) == 'offro' %\}"
            r"(?:(?!\{% endif %\}).)*?\{\{ availability_badge\(",
            search,
            flags=re.DOTALL,
        )
        self.assertEqual(len(guarded_badges), 3)

    def test_sought_schedule_summary_reaches_search_and_profile_cards(self):
        search = self.read_template("cerca.html")
        dashboard = self.read_template("dashboard.html")

        self.assertEqual(search.count("{{ sought_availability_badge("), 3)
        self.assertEqual(dashboard.count("{{ sought_availability_badge("), 1)

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
        self.assertEqual(dashboard.count("show_schedule=true"), 1)
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
            ".sought-availability-card",
            ".sought-availability-compact",
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

    def test_unavailable_save_does_not_offer_permanent_listing_deletion(self):
        dialog = self.read_template(
            "partials/disponibilita_servizi_dialog.html"
        )

        self.assertNotIn('id="service-availability-listing-choice"', dialog)
        self.assertNotIn('id="service-availability-listing-keep"', dialog)
        self.assertNotIn('id="service-availability-listing-delete"', dialog)
        self.assertNotIn("selectedListingForDeletion()", dialog)
        self.assertNotIn("showListingChoice(data", dialog)
        self.assertNotIn("fetch(`/api/annunci/${listing.id}/elimina`", dialog)

    def test_save_refreshes_after_automatic_archive_without_second_choice(self):
        dialog = self.read_template(
            "partials/disponibilita_servizi_dialog.html"
        )

        save_start = dialog.index("async function saveAvailability")
        save_end = dialog.index("async function deleteAvailability", save_start)
        save_body = dialog[save_start:save_end]
        self.assertIn("window.location.reload()", save_body)
        self.assertNotIn("showListingChoice", save_body)
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
