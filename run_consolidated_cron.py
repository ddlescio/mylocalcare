"""Entrypoint Render per tutte le attivita pianificate di MyLocalCare."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


from consolidated_cron import (  # noqa: E402
    CronLedger,
    build_app_handlers,
    build_task_plan,
    execute_plan,
)


def _consolidated_cron_enabled():
    # Richiediamo il valore letterale "true": l'assenza della variabile, "1"
    # o qualunque refuso mantengono il dispatcher in modalita fail-closed.
    return os.getenv("CONSOLIDATED_CRON_ENABLED", "").strip().lower() == "true"


def _dry_run_report(plan):
    required_env = {
        "chat_email_reminders": ("POSTMARK_SERVER_TOKEN",),
        "availability_daily": ("POSTMARK_SERVER_TOKEN",),
        "incomplete_profiles_weekly": ("POSTMARK_SERVER_TOKEN",),
        "openai_monthly_save": ("OPENAI_ADMIN_KEY",),
    }
    tasks = []
    required_for_full_schedule = (
        "POSTMARK_SERVER_TOKEN",
        "OPENAI_ADMIN_KEY",
    )
    globally_missing = [
        name for name in required_for_full_schedule
        if not os.getenv(name, "").strip()
    ]
    missing_any = bool(globally_missing)
    for task in plan:
        missing = [
            name for name in required_env.get(task.handler_name, ())
            if not os.getenv(name, "").strip()
        ]
        missing_any = missing_any or bool(missing)
        tasks.append({
            "task": task.key,
            "scheduled_for": task.scheduled_for.isoformat(),
            "would_run": True,
            # Non mostra mai valori o frammenti dei segreti.
            "missing_environment": missing,
        })
    return {
        "ok": not missing_any,
        "dry_run": True,
        "missing_environment_for_full_schedule": globally_missing,
        "tasks": tasks,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Esegue il cron consolidato MyLocalCare.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Verifica migrazione, piano e presenza delle variabili protette "
            "senza acquisire claim, modificare il database o inviare avvisi."
        ),
    )
    args = parser.parse_args(argv)

    if not args.dry_run and not _consolidated_cron_enabled():
        print(json.dumps({
            "ok": True,
            "enabled": False,
            "reason": (
                "Cron consolidato disattivato: impostare esplicitamente "
                "CONSOLIDATED_CRON_ENABLED=true soltanto dopo migrazione, "
                "copia delle variabili protette e dry-run riuscito."
            ),
            "tasks_executed": 0,
        }, ensure_ascii=False, sort_keys=True), flush=True)
        # Stato atteso durante il rollout, non un guasto del servizio Render.
        return 0

    # Forzato (non setdefault) immediatamente prima dell'import applicativo:
    # un valore ereditato non deve trasformare questo processo in un worker
    # web/realtime con loop permanenti. Tenerlo qui evita effetti collaterali
    # quando i test importano soltanto gli helper dry-run del runner.
    os.environ["RUNTIME_SERVICE"] = "job"
    import app as app_module

    if not app_module.app.config.get("IS_POSTGRES"):
        print(json.dumps({
            "ok": False,
            "error": "Il cron consolidato richiede PostgreSQL.",
        }), flush=True)
        return 1

    ledger = CronLedger(
        app_module.get_db_connection,
        app_module.get_cursor,
        app_module.sql,
    )

    # Controllo fail-closed: nessun handler viene costruito o invocato prima
    # che il ledger persistente sia disponibile e completo.
    try:
        ledger.assert_ready()
    except Exception as error:
        print(json.dumps({
            "ok": False,
            "error": str(error),
        }, ensure_ascii=False), flush=True)
        return 1

    now = datetime.now(timezone.utc)
    plan = build_task_plan(now)

    if args.dry_run:
        report = _dry_run_report(plan)
        report["enabled"] = _consolidated_cron_enabled()
        print(
            json.dumps(report, ensure_ascii=False, sort_keys=True),
            flush=True,
        )
        return 0 if report.get("ok") else 1

    with app_module.app.app_context():
        handlers = build_app_handlers(app_module)
        report = execute_plan(
            ledger,
            plan,
            handlers,
            now=now,
        )

    print(
        json.dumps(report, ensure_ascii=False, default=str, sort_keys=True),
        flush=True,
    )
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
