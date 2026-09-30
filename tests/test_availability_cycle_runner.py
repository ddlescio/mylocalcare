import contextlib
import io
import json
import sys
import types
import unittest
from unittest.mock import patch

import run_availability_reminders


class _AppContext:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _Connection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class AvailabilityCycleRunnerTest(unittest.TestCase):
    def test_runner_esegue_promemoria_ciclo_e_pulizia_nello_stesso_batch(self):
        calls = []
        connection = _Connection()

        fake_app_module = types.ModuleType("app")
        fake_app_module.app = types.SimpleNamespace(
            app_context=lambda: _AppContext(),
            config={"IS_POSTGRES": False},
        )
        fake_app_module.get_db_connection = lambda: connection

        def reminders(*, limite, dry_run):
            calls.append(("reminders", limite, dry_run))
            return {"ok": True, "promemoria": 2}

        def lifecycle(*, limite, dry_run):
            calls.append(("lifecycle", limite, dry_run))
            return {"ok": True, "annunci_archiviati": 1}

        fake_app_module.processa_promemoria_disponibilita = reminders
        fake_app_module.processa_ciclo_disponibilita_annunci = lifecycle

        fake_access_module = types.ModuleType("accessi_utenti")

        def cleanup(conn, *, postgres):
            calls.append(("cleanup", conn, postgres))
            return 4

        fake_access_module.elimina_accessi_scaduti = cleanup

        output = io.StringIO()
        with patch.dict(
            sys.modules,
            {"app": fake_app_module, "accessi_utenti": fake_access_module},
        ), contextlib.redirect_stdout(output):
            result = run_availability_reminders.main(["--limit", "25"])

        self.assertEqual(result, 0)
        self.assertEqual(calls[0], ("reminders", 25, False))
        self.assertEqual(calls[1], ("lifecycle", 500, False))
        self.assertEqual(calls[2], ("cleanup", connection, False))
        self.assertTrue(connection.closed)

        payload = json.loads(output.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["ciclo_annunci"]["annunci_archiviati"], 1)
        self.assertEqual(payload["accessi_eliminati"], 4)

    def test_esito_runner_fallisce_se_il_ciclo_annunci_fallisce(self):
        fake_app_module = types.ModuleType("app")
        fake_app_module.app = types.SimpleNamespace(
            app_context=lambda: _AppContext(),
            config={"IS_POSTGRES": False},
        )
        fake_app_module.get_db_connection = lambda: _Connection()
        fake_app_module.processa_promemoria_disponibilita = (
            lambda **kwargs: {"ok": True}
        )
        fake_app_module.processa_ciclo_disponibilita_annunci = (
            lambda **kwargs: {"ok": False, "error": "DatabaseError"}
        )

        fake_access_module = types.ModuleType("accessi_utenti")
        fake_access_module.elimina_accessi_scaduti = (
            lambda conn, postgres: 0
        )

        with patch.dict(
            sys.modules,
            {"app": fake_app_module, "accessi_utenti": fake_access_module},
        ), contextlib.redirect_stdout(io.StringIO()):
            result = run_availability_reminders.main(["--dry-run"])

        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
