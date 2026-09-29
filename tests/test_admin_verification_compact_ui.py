from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
REFERENCES = (ROOT / "templates" / "admin_referenze.html").read_text(
    encoding="utf-8"
)
PROFILE_CARDS = (
    ROOT / "templates" / "admin_schede_profilo.html"
).read_text(encoding="utf-8")


class AdminVerificationCompactUiTests(unittest.TestCase):
    def assert_collapsed_details(self, source, data_attribute):
        tag = re.search(
            rf"<details\b[^>]*\b{re.escape(data_attribute)}(?:=(?:\"[^\"]*\"|'[^']*'))?[^>]*>",
            source,
        )
        self.assertIsNotNone(tag, f"Dettaglio {data_attribute} non trovato")
        self.assertNotRegex(tag.group(0), r"\sopen(?:\s|=|>)")

    def test_both_pages_use_compact_headers_and_inline_stats(self):
        for source, label in (
            (REFERENCES, "Riepilogo referenze"),
            (PROFILE_CARDS, "Riepilogo schede profilo"),
        ):
            with self.subTest(label=label):
                self.assertIn('class="admin-compact-header', source)
                self.assertIn('class="admin-compact-stats flex flex-wrap gap-2"', source)
                self.assertIn(f'aria-label="{label}"', source)
                self.assertNotIn("sm:p-7", source)

    def test_page_instructions_are_in_closed_native_accordions(self):
        self.assert_collapsed_details(REFERENCES, "data-admin-guide")
        self.assert_collapsed_details(PROFILE_CARDS, "data-admin-guide")

        reference_guide = REFERENCES.index('data-admin-guide="referenze"')
        profile_guide = PROFILE_CARDS.index(
            'data-admin-guide="schede-profilo"'
        )
        self.assertGreater(
            REFERENCES.index("Controlla le risposte inviate", reference_guide),
            reference_guide,
        )
        self.assertGreater(
            PROFILE_CARDS.index("Le schede sono visibili subito", profile_guide),
            profile_guide,
        )
        self.assertLess(reference_guide, REFERENCES.index('<form method="get"'))
        self.assertLess(profile_guide, PROFILE_CARDS.index('<form method="get"'))

    def test_filter_forms_are_collapsed_to_reach_work_items_quickly(self):
        self.assert_collapsed_details(
            REFERENCES,
            'data-admin-filters="referenze"',
        )
        self.assert_collapsed_details(
            PROFILE_CARDS,
            'data-admin-filters="schede-profilo"',
        )
        self.assertIn("stato_filtro_referenze", REFERENCES)
        self.assertIn("filtri_referenze_personalizzati", REFERENCES)
        self.assertIn("stato_filtro_schede", PROFILE_CARDS)
        self.assertIn("filtri_schede_personalizzati", PROFILE_CARDS)

    def test_profile_card_long_help_is_collapsed_but_actions_stay_visible(self):
        self.assert_collapsed_details(PROFILE_CARDS, "data-admin-request-guide")
        self.assert_collapsed_details(PROFILE_CARDS, "data-admin-decision-guide")
        self.assertIn("Come concordare il controllo (non inviare documenti)", PROFILE_CARDS)
        self.assertIn("Guida a controllo, esiti e metodo", PROFILE_CARDS)
        for action in ("💬 Chat", "✉️ Mail", "👤 Profilo", "Registra controllo"):
            self.assertIn(action, PROFILE_CARDS)

    def test_reference_history_and_publication_help_are_collapsed(self):
        self.assert_collapsed_details(REFERENCES, "data-admin-audit-history")
        self.assert_collapsed_details(REFERENCES, "data-admin-publication-guide")
        for status in ("removed", "pending", "denied", "unavailable", "available"):
            self.assert_collapsed_details(
                REFERENCES,
                f'data-contact-status="{status}"',
            )
        self.assertIn("Decisione editoriale finale", REFERENCES)
        self.assertIn('name="pubblicazione_approvata_admin"', REFERENCES)
        self.assertIn("Chiama il referente", REFERENCES)
        self.assertIn("Registra esito", REFERENCES)
        self.assertIn("Elimina referenza", REFERENCES)

    def test_admin_reference_navigation_uses_like_icon(self):
        for template in ("layout_admin.html", "admin_dashboard.html"):
            source = (ROOT / "templates" / template).read_text(encoding="utf-8")
            with self.subTest(template=template):
                self.assertIn("👍", source)
                self.assertNotIn("🤝", source)


if __name__ == "__main__":
    unittest.main()
