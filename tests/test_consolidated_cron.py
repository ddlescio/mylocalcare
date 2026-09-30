import unittest
from datetime import datetime, timezone
import os
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from consolidated_cron import (
    ScheduledTask,
    build_task_plan,
    execute_plan,
    openai_monthly_slot,
    quarter_hour_slot,
)
from run_consolidated_cron import _dry_run_report, main as cron_main


ROOT = Path(__file__).resolve().parents[1]
UTC = timezone.utc


class FakeLedger:
    def __init__(self):
        self.claimed = []
        self.completed = []
        self.failed = []

    def claim(self, task, *, now):
        self.claimed.append((task.key, task.scheduled_for, now))
        return f"token-{task.key}"

    def complete(self, task, token, result):
        self.completed.append((task.key, token, result))

    def fail(self, task, token, error, *, retry_minutes=5):
        self.failed.append((task.key, token, str(error), retry_minutes))


class StatefulFakeLedger(FakeLedger):
    def __init__(self):
        super().__init__()
        self.done = set()

    def claim(self, task, *, now):
        identity = (task.key, task.scheduled_for)
        if identity in self.done:
            return None
        return super().claim(task, now=now)

    def complete(self, task, token, result):
        super().complete(task, token, result)
        self.done.add((task.key, task.scheduled_for))


class ConsolidatedCronScheduleTests(unittest.TestCase):
    def test_quarter_hour_slot_is_stable(self):
        now = datetime(2026, 9, 30, 21, 14, 59, tzinfo=UTC)
        self.assertEqual(
            quarter_hour_slot(now),
            datetime(2026, 9, 30, 21, 0, tzinfo=UTC),
        )

    def test_plan_contains_frequent_and_due_tasks(self):
        # Mercoledi 30 settembre, dopo il salvataggio OpenAI.
        now = datetime(2026, 9, 30, 23, 0, tzinfo=UTC)
        plan = build_task_plan(now)
        by_key = {task.key: task for task in plan}

        self.assertEqual(
            {
                "sync_servizi_scaduti",
                "referenze_outbox_recovery",
                "chat_email_reminders",
                "availability_daily",
                "openai_monthly_save",
            },
            set(by_key),
        )
        self.assertEqual(
            by_key["availability_daily"].scheduled_for,
            datetime(2026, 9, 30, 8, 15, tzinfo=UTC),
        )
        self.assertEqual(
            by_key["openai_monthly_save"].scheduled_for,
            datetime(2026, 9, 30, 22, 50, tzinfo=UTC),
        )

    def test_weekly_profile_task_starts_after_transition_grace(self):
        before = build_task_plan(
            datetime(2026, 10, 4, 18, 14, tzinfo=UTC)
        )
        after = build_task_plan(
            datetime(2026, 10, 4, 18, 15, tzinfo=UTC)
        )
        self.assertNotIn(
            "incomplete_profiles_weekly",
            {task.key for task in before},
        )
        by_key = {task.key: task for task in after}
        self.assertEqual(
            by_key["incomplete_profiles_weekly"].scheduled_for,
            datetime(2026, 10, 4, 18, 0, tzinfo=UTC),
        )
        self.assertEqual(
            by_key["incomplete_profiles_weekly"].retry_minutes,
            7 * 24 * 60,
        )

    def test_daily_task_does_not_run_before_its_time(self):
        before = build_task_plan(
            datetime(2026, 9, 30, 8, 14, tzinfo=UTC)
        )
        self.assertNotIn(
            "availability_daily",
            {task.key for task in before},
        )

    def test_openai_task_is_not_due_before_window(self):
        self.assertIsNone(openai_monthly_slot(
            datetime(2026, 9, 27, 23, 59, tzinfo=UTC)
        ))
        self.assertIsNone(openai_monthly_slot(
            datetime(2026, 9, 28, 22, 49, tzinfo=UTC)
        ))
        self.assertIsNotNone(openai_monthly_slot(
            datetime(2026, 9, 28, 22, 50, tzinfo=UTC)
        ))

    def test_failure_is_isolated_and_reported(self):
        now = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
        tasks = [
            ScheduledTask("one", now, "one"),
            ScheduledTask("two", now, "two"),
        ]
        ledger = FakeLedger()

        def fail():
            raise RuntimeError("errore atteso")

        report = execute_plan(
            ledger,
            tasks,
            {"one": fail, "two": lambda: {"ok": True}},
            now=now,
        )

        self.assertFalse(report["ok"])
        self.assertEqual([row[0] for row in ledger.failed], ["one"])
        self.assertEqual([row[0] for row in ledger.completed], ["two"])

    def test_explicit_unsuccessful_result_is_failure(self):
        now = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
        task = ScheduledTask("one", now, "one")
        ledger = FakeLedger()
        report = execute_plan(
            ledger,
            [task],
            {"one": lambda: {"ok": False, "error": "provider"}},
            now=now,
        )
        self.assertFalse(report["ok"])
        self.assertEqual(len(ledger.failed), 1)
        self.assertEqual(ledger.completed, [])

    def test_same_slot_is_executed_only_once(self):
        now = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
        tasks = [
            ScheduledTask("one", now, "one"),
            ScheduledTask("two", now, "two"),
        ]
        calls = {"one": 0, "two": 0}

        def handler(name):
            def run():
                calls[name] += 1
                return {"ok": True}
            return run

        handlers = {"one": handler("one"), "two": handler("two")}
        ledger = StatefulFakeLedger()
        first = execute_plan(ledger, tasks, handlers, now=now)
        second = execute_plan(ledger, tasks, handlers, now=now)

        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertEqual(calls, {"one": 1, "two": 1})
        self.assertEqual(
            [item["status"] for item in second["tasks"]],
            ["already_claimed_or_completed", "already_claimed_or_completed"],
        )


class ConsolidatedCronConfigurationTests(unittest.TestCase):
    def test_render_blueprint_has_one_consolidated_cron(self):
        body = (ROOT / "render.yaml").read_text(encoding="utf-8")
        self.assertEqual(body.count("- type: cron"), 1)
        self.assertIn("name: localcare-sync-servizi-scaduti", body)
        self.assertIn('schedule: "*/15 * * * *"', body)
        self.assertIn("python run_consolidated_cron.py", body)
        self.assertNotIn("name: localcare-promemoria-disponibilita", body)

    def test_runner_forces_job_role_before_app_import(self):
        body = (ROOT / "run_consolidated_cron.py").read_text(
            encoding="utf-8"
        )
        role_position = body.index('os.environ["RUNTIME_SERVICE"] = "job"')
        app_position = body.index("import app as app_module")
        self.assertLess(role_position, app_position)

    def test_normal_runner_is_fail_closed_until_explicitly_enabled(self):
        output = StringIO()
        with patch.dict(os.environ, {}, clear=True), patch("sys.stdout", output):
            exit_code = cron_main([])
        self.assertEqual(exit_code, 0)
        report = __import__("json").loads(output.getvalue())
        self.assertTrue(report["ok"])
        self.assertFalse(report["enabled"])
        self.assertEqual(report["tasks_executed"], 0)

    def test_blueprint_keeps_activation_manually_managed_and_fail_closed(self):
        body = (ROOT / "render.yaml").read_text(encoding="utf-8")
        self.assertIn(
            "- key: CONSOLIDATED_CRON_ENABLED\n        sync: false",
            body,
        )
        self.assertNotIn(
            "- key: CONSOLIDATED_CRON_ENABLED\n        value:",
            body,
        )

    def test_dry_run_reports_missing_env_without_secret_values(self):
        task = ScheduledTask(
            "chat_email_reminders",
            datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
            "chat_email_reminders",
        )
        with patch.dict(os.environ, {}, clear=True):
            report = _dry_run_report([task])
        self.assertTrue(report["dry_run"])
        self.assertEqual(
            report["tasks"][0]["missing_environment"],
            ["POSTMARK_SERVER_TOKEN"],
        )
        self.assertEqual(
            report["missing_environment_for_full_schedule"],
            ["POSTMARK_SERVER_TOKEN", "OPENAI_ADMIN_KEY"],
        )
        self.assertNotIn("environment_value", report["tasks"][0])

    def test_migration_defines_unique_schedule_and_retry_fields(self):
        body = (
            ROOT / "migrations" / "20260930_cron_task_ledger.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("PRIMARY KEY (task_key, scheduled_for)", body)
        self.assertIn("lease_expires_at", body)
        self.assertIn("next_retry_at", body)
        self.assertIn("claim_token UUID", body)


if __name__ == "__main__":
    unittest.main()
