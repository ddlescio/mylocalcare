import re
import unittest
from pathlib import Path

from i18n import translate_source
from i18n_catalog import PHRASE_ROWS


class AvailabilityReminderDeployTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]
    SOURCES = (
        "Riconferma la tua disponibilità",
        (
            "È passato circa un mese dall’ultima conferma. Controlla i dati "
            "già salvati: puoi riconfermarli così come sono oppure modificarli."
        ),
        "Riconferma la tua disponibilità su MyLocalCare",
        "Controlla disponibilità",
    )

    def test_render_configures_daily_availability_reminder_cron(self):
        source = (self.ROOT / "render.yaml").read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^    - type: cron\n"
            r"      name: localcare-promemoria-disponibilita\n"
            r"(?P<body>.*?)(?=^    - type:|\Z)",
            source,
        )
        self.assertIsNotNone(match, "Cron disponibilità assente da render.yaml")
        body = match.group("body")

        self.assertIn("startCommand: python run_availability_reminders.py", body)
        self.assertIn('schedule: "15 8 * * *"', body)
        self.assertIn("autoDeployTrigger: commit", body)

        for key in (
            "APP_BASE_URL",
            "DATABASE_URL",
            "REDIS_URL",
            "MAIL_USERNAME",
            "MAIL_PASSWORD",
            "MAIL_FROM_ADDRESS",
            "MAIL_FROM_NAME",
            "POSTMARK_SERVER_TOKEN",
            "POSTMARK_MESSAGE_STREAM",
            "VAPID_PUBLIC_KEY",
            "VAPID_PRIVATE_KEY",
            "VAPID_CLAIM_EMAIL",
        ):
            self.assertIn(f"- key: {key}", body, key)

    def test_reminder_copy_has_exactly_the_five_catalog_languages(self):
        rows = {row[0]: row for row in PHRASE_ROWS}

        for source in self.SOURCES:
            self.assertIn(source, rows)
            self.assertEqual(len(rows[source]), 5, source)
            for translation in rows[source]:
                self.assertTrue(translation.strip(), source)

        self.assertEqual(
            translate_source("Riconferma la tua disponibilità", "en"),
            "Reconfirm your availability",
        )
        self.assertEqual(
            translate_source("Controlla disponibilità", "de"),
            "Verfügbarkeit prüfen",
        )
        self.assertEqual(
            translate_source("Riconferma la tua disponibilità", "ro"),
            "Reconfirmă-ți disponibilitatea",
        )
        self.assertEqual(
            translate_source("Riconferma la tua disponibilità", "uk"),
            "Підтвердьте свою доступність ще раз",
        )
        self.assertEqual(
            translate_source("Riconferma la tua disponibilità", "fil"),
            "Kumpirmahing muli ang iyong availability",
        )


if __name__ == "__main__":
    unittest.main()
