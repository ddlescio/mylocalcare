import json
import re
import unittest
from pathlib import Path


class AiWritingLanguageFlowTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]
    TEMPLATE_NAMES = ("nuovo_annuncio.html", "modifica_annuncio.html")

    @classmethod
    def setUpClass(cls):
        cls.templates = {
            name: (cls.ROOT / "templates" / name).read_text(encoding="utf-8")
            for name in cls.TEMPLATE_NAMES
        }
        cls.translations = json.loads(
            (cls.ROOT / "static" / "data" / "ai_writing_texts.json").read_text(
                encoding="utf-8"
            )
        )
        cls.app_source = (cls.ROOT / "app.py").read_text(encoding="utf-8")

    def test_action_choice_is_replaced_by_a_short_translation_note(self):
        for name, source in self.templates.items():
            with self.subTest(template=name):
                self.assertNotIn('id="ai-writing-action"', source)
                self.assertNotIn('id="ai-writing-action-label"', source)
                self.assertNotIn("Migliora ora e lasciamo nella tua lingua", source)
                self.assertNotIn(
                    "Migliora ora e traduciamo in italiano alla fine", source
                )
                self.assertEqual(source.count('id="ai-writing-translation-note"'), 1)
                self.assertIn(
                    "La proposta resta nella lingua scelta. "
                    "Nell’annuncio sarà inserita in italiano.",
                    source,
                )

    def test_preview_stays_in_selected_language_and_use_always_translates(self):
        for name, source in self.templates.items():
            with self.subTest(template=name):
                self.assertIn('const previewAction = "improve";', source)
                self.assertIn(
                    'const shouldTranslateBeforeUse = selectedLanguage !== "it";',
                    source,
                )
                self.assertIn('azione: "final_translate_it"', source)
                self.assertNotIn("lastUseIntent", source)
                self.assertNotIn("actionSelect", source)

    def test_every_selectable_non_italian_language_has_the_note(self):
        language_sets = []

        for name, source in self.templates.items():
            select = re.search(
                r'<select\s+id="ai-writing-ui-language".*?</select>',
                source,
                flags=re.DOTALL,
            )
            self.assertIsNotNone(select, name)
            language_sets.append(set(re.findall(r'<option value="([^"]+)"', select.group())))

        self.assertEqual(language_sets[0], language_sets[1])
        expected_external_languages = language_sets[0] - {"it"}
        self.assertEqual(expected_external_languages, set(self.translations))

        for language, values in self.translations.items():
            with self.subTest(language=language):
                subtitle = values.get("subtitle")
                note = values.get("translationNote")
                self.assertIsInstance(subtitle, str)
                self.assertTrue(subtitle.strip())
                self.assertIsInstance(note, str)
                self.assertTrue(note.strip())
                self.assertTrue(
                    {"actionLabel", "improve", "translate"}.isdisjoint(values)
                )

        self.assertEqual(
            self.translations["en"]["subtitle"],
            "Write in the language you prefer: the proposal will stay in that language.",
        )
        self.assertEqual(
            self.translations["en"]["translationNote"],
            "The text stays in the selected language. When you use it in your "
            "listing, it will be translated into Italian.",
        )

    def test_ai_prompt_outputs_preview_in_selected_language(self):
        self.assertIn(
            'restituisci sempre titolo e descrizione nella "lingua_scelta"',
            self.app_source,
        )
        self.assertIn(
            'traducilo e adattalo alla "lingua_scelta" mentre lo migliori',
            self.app_source,
        )
        self.assertNotIn(
            "mantenendo la lingua effettiva del testo originale", self.app_source
        )


if __name__ == "__main__":
    unittest.main()
