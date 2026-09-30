import importlib.util
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from i18n import LEGAL_DOCUMENT_VERSION, translate


ROOT = Path(__file__).resolve().parents[1]


def load_init_db_without_flask():
    fake_app_module = types.ModuleType("app")
    fake_app_module.app = object()
    fake_app_module.sql = lambda query: query
    fake_app_module.now_sql = lambda: "CURRENT_TIMESTAMP"

    module_name = "init_db_notification_preferences_test"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "init_db.py")
    module = importlib.util.module_from_spec(spec)
    original_directory = Path.cwd()
    with tempfile.TemporaryDirectory() as isolated_directory:
        try:
            os.chdir(isolated_directory)
            with mock.patch.dict(
                sys.modules,
                {"app": fake_app_module, module_name: module},
            ), mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DATABASE_URL", None)
                spec.loader.exec_module(module)
        finally:
            os.chdir(original_directory)
    return module


class NotificationPreferencesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.init_db = load_init_db_without_flask()

    def test_new_accounts_default_to_email_and_push_enabled(self):
        temporary = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temporary.close()
        database_path = Path(temporary.name)

        def connect():
            connection = sqlite3.connect(database_path)
            connection.row_factory = sqlite3.Row
            return connection

        try:
            with mock.patch.object(self.init_db, "get_conn", side_effect=connect):
                self.init_db.crea_tabella_utenti()

            connection = connect()
            connection.execute(
                """
                INSERT INTO utenti (nome, cognome, email, username, password)
                VALUES ('Mario', 'Rossi', 'mario@example.test', 'MARIO', 'hash')
                """
            )
            row = connection.execute(
                "SELECT email_notifiche, push_notifiche FROM utenti"
            ).fetchone()
            connection.close()

            self.assertEqual(row["email_notifiche"], 1)
            self.assertEqual(row["push_notifiche"], 1)
        finally:
            database_path.unlink(missing_ok=True)

    def test_postgres_migration_backfills_and_requires_push_preference(self):
        migration = (
            ROOT / "migrations" / "20260930_preferenze_notifiche.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("ADD COLUMN IF NOT EXISTS push_notifiche INTEGER", migration)
        self.assertIn("SET push_notifiche = 1", migration)
        self.assertIn("ALTER COLUMN push_notifiche SET DEFAULT 1", migration)
        self.assertIn("ALTER COLUMN push_notifiche SET NOT NULL", migration)

    def test_server_preference_is_respected_by_push_paths(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn('column_name = \'push_notifiche\'', source)
        self.assertIn("preferenza account disattivata", source)
        self.assertIn('"code": "push_preference_disabled"', source)
        self.assertIn(
            '@app.route("/impostazioni/notifiche-push", methods=["POST"])',
            source,
        )
        self.assertIn("DELETE FROM push_subscriptions", source)

    def test_browser_permission_is_not_bypassed(self):
        base = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
        settings = (
            ROOT / "templates" / "impostazioni.html"
        ).read_text(encoding="utf-8")
        self.assertIn("Notification.requestPermission()", base)
        self.assertIn("myLocalCarePushPreferenceEnabled", base)
        self.assertIn("myLocalCarePushPreferenceEnabled", settings)
        self.assertIn("pushDeviceEnableBtn", settings)

    def test_optional_and_essential_email_copy_are_separate(self):
        settings = (
            ROOT / "templates" / "impostazioni.html"
        ).read_text(encoding="utf-8")
        privacy = (ROOT / "templates" / "privacy.html").read_text(
            encoding="utf-8"
        )
        terms = (ROOT / "templates" / "termini.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("settings.optional_email_title", settings)
        self.assertIn("settings.essential_listing_email_body", settings)
        self.assertIn("legal.essential_listing_email_privacy", privacy)
        self.assertIn("legal.essential_listing_email_terms", terms)
        self.assertEqual(
            translate("settings.optional_email_title", "en"),
            "Optional email alerts",
        )
        self.assertIn("2026_v6", LEGAL_DOCUMENT_VERSION)


if __name__ == "__main__":
    unittest.main()
