"""Pianificazione e ledger del cron Render consolidato.

Il modulo non importa :mod:`app` a livello globale: il runner puo quindi
verificare la presenza della migrazione del ledger *prima* di eseguire
qualsiasi attivita applicativa. Tutte le date di pianificazione sono UTC.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import uuid


UTC = timezone.utc
LEDGER_TABLE = "cron_task_ledger"


@dataclass(frozen=True)
class ScheduledTask:
    key: str
    scheduled_for: datetime
    handler_name: str
    retry_minutes: int = 5


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def quarter_hour_slot(now: datetime) -> datetime:
    now = _as_utc(now)
    return now.replace(
        minute=(now.minute // 15) * 15,
        second=0,
        microsecond=0,
    )


def daily_slot_if_due(
    now: datetime,
    hour: int,
    minute: int,
) -> datetime | None:
    """Scadenza odierna, solo quando l'orario previsto e gia trascorso."""

    now = _as_utc(now)
    candidate = now.replace(
        hour=hour,
        minute=minute,
        second=0,
        microsecond=0,
    )
    return candidate if candidate <= now else None


def weekly_slot_if_due(
    now: datetime,
    *,
    weekday: int,
    hour: int,
    minute: int,
) -> datetime | None:
    """Scadenza della settimana corrente, solo nel giorno previsto.

    ``weekday`` segue ``datetime.weekday`` (lunedi=0, domenica=6).
    Il quarto d'ora di tolleranza evita la corsa con il vecchio cron delle
    18:00 durante il passaggio: il controllo anti-doppione applicativo ha il
    tempo di vedere il promemoria appena creato.
    """

    now = _as_utc(now)
    if now.weekday() != weekday:
        return None
    candidate = now.replace(
        hour=hour,
        minute=minute,
        second=0,
        microsecond=0,
    )
    return candidate if now >= candidate + timedelta(minutes=15) else None


def openai_monthly_slot(now: datetime) -> datetime | None:
    """Scadenza giornaliera OpenAI dei giorni 28-31 dopo le 22:50 UTC."""

    now = _as_utc(now)
    if now.day < 28:
        return None
    candidate = now.replace(hour=22, minute=50, second=0, microsecond=0)
    if candidate > now:
        return None
    return candidate


def build_task_plan(now: datetime) -> list[ScheduledTask]:
    """Costruisce il piano per una singola invocazione ogni 15 minuti."""

    now = _as_utc(now)
    frequent_slot = quarter_hour_slot(now)
    plan = [
        # Prima i promemoria sensibili al tempo; il vecchio sync servizi puo
        # richiedere decine di secondi e non deve ritardare le email chat.
        ScheduledTask(
            "chat_email_reminders",
            frequent_slot,
            "chat_email_reminders",
        ),
        ScheduledTask(
            "referenze_outbox_recovery",
            frequent_slot,
            "referenze_outbox_recovery",
        ),
        ScheduledTask(
            "sync_servizi_scaduti",
            frequent_slot,
            "sync_servizi_scaduti",
        ),
    ]

    availability_slot = daily_slot_if_due(now, 8, 15)
    if availability_slot is not None:
        plan.append(ScheduledTask(
            "availability_daily",
            availability_slot,
            "availability_daily",
        ))

    profiles_slot = weekly_slot_if_due(
        now,
        weekday=6,
        hour=18,
        minute=0,
    )
    if profiles_slot is not None:
        plan.append(ScheduledTask(
            "incomplete_profiles_weekly",
            profiles_slot,
            "incomplete_profiles_weekly",
            # Questa funzione invia email dentro un batch e conferma il DB al
            # termine. Dopo un crash ambiguo non la ripetiamo nella stessa
            # settimana, evitando una seconda email agli utenti gia raggiunti.
            retry_minutes=7 * 24 * 60,
        ))

    openai_slot = openai_monthly_slot(now)
    if openai_slot is not None:
        plan.append(ScheduledTask(
            "openai_monthly_save",
            openai_slot,
            "openai_monthly_save",
        ))

    return plan


class CronLedger:
    """Claim persistenti con lease, retry e completamento tokenizzato."""

    REQUIRED_COLUMNS = {
        "task_key",
        "scheduled_for",
        "status",
        "claim_token",
        "attempt_count",
        "lease_expires_at",
        "next_retry_at",
        "result_json",
    }

    def __init__(self, connection_factory, cursor_factory, sql_adapter):
        self._connection_factory = connection_factory
        self._cursor_factory = cursor_factory
        self._sql = sql_adapter

    def assert_ready(self) -> None:
        """Fallisce prima dei task se la migrazione non e completa."""

        conn = self._connection_factory()
        cur = self._cursor_factory(conn)
        try:
            cur.execute("""
                SELECT to_regclass('public.cron_task_ledger') AS relation
            """)
            row = cur.fetchone()
            relation = row["relation"] if row else None
            if not relation:
                raise RuntimeError(
                    "Migrazione cron mancante: eseguire "
                    "migrations/20260930_cron_task_ledger.sql prima di "
                    "attivare il cron consolidato. Nessun task eseguito."
                )

            cur.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'cron_task_ledger'
            """)
            columns = {row["column_name"] for row in cur.fetchall()}
            missing = sorted(self.REQUIRED_COLUMNS - columns)
            if missing:
                raise RuntimeError(
                    "Migrazione cron incompleta; colonne mancanti: "
                    + ", ".join(missing)
                    + ". Nessun task eseguito."
                )
            conn.rollback()
        finally:
            try:
                cur.close()
            finally:
                conn.close()

    def claim(
        self,
        task: ScheduledTask,
        *,
        now: datetime,
        lease_minutes: int = 60,
    ) -> str | None:
        token = str(uuid.uuid4())
        now = _as_utc(now)
        lease_expires = now + timedelta(minutes=max(5, lease_minutes))
        conn = self._connection_factory()
        cur = self._cursor_factory(conn)
        try:
            cur.execute(self._sql("""
                INSERT INTO cron_task_ledger (
                    task_key, scheduled_for, status, claim_token,
                    attempt_count, claimed_at, lease_expires_at,
                    completed_at, next_retry_at, last_error,
                    result_json, created_at, updated_at
                )
                VALUES (?, ?, 'running', ?, 1, ?, ?, NULL, NULL, NULL,
                        NULL, ?, ?)
                ON CONFLICT (task_key, scheduled_for) DO UPDATE SET
                    status = 'running',
                    claim_token = EXCLUDED.claim_token,
                    attempt_count = cron_task_ledger.attempt_count + 1,
                    claimed_at = EXCLUDED.claimed_at,
                    lease_expires_at = EXCLUDED.lease_expires_at,
                    completed_at = NULL,
                    next_retry_at = NULL,
                    last_error = NULL,
                    updated_at = EXCLUDED.updated_at
                WHERE (
                    cron_task_ledger.status = 'failed'
                    AND (
                        cron_task_ledger.next_retry_at IS NULL
                        OR cron_task_ledger.next_retry_at <= ?
                    )
                ) OR (
                    cron_task_ledger.status = 'running'
                    AND cron_task_ledger.lease_expires_at <= ?
                )
                RETURNING claim_token
            """), (
                task.key,
                task.scheduled_for,
                token,
                now,
                lease_expires,
                now,
                now,
                now,
                now,
            ))
            claimed = cur.fetchone()
            conn.commit()
            if not claimed:
                return None
            return str(claimed["claim_token"])
        except Exception:
            conn.rollback()
            raise
        finally:
            try:
                cur.close()
            finally:
                conn.close()

    def complete(self, task: ScheduledTask, token: str, result) -> None:
        normalized = json.dumps(result, ensure_ascii=False, default=str)
        conn = self._connection_factory()
        cur = self._cursor_factory(conn)
        try:
            cur.execute(self._sql("""
                UPDATE cron_task_ledger
                SET status = 'completed',
                    completed_at = CURRENT_TIMESTAMP,
                    lease_expires_at = NULL,
                    next_retry_at = NULL,
                    last_error = NULL,
                    result_json = ?::jsonb,
                    updated_at = CURRENT_TIMESTAMP
                WHERE task_key = ?
                  AND scheduled_for = ?
                  AND status = 'running'
                  AND claim_token = ?
            """), (
                normalized,
                task.key,
                task.scheduled_for,
                token,
            ))
            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Claim perso durante il completamento di {task.key}."
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            try:
                cur.close()
            finally:
                conn.close()

    def fail(
        self,
        task: ScheduledTask,
        token: str,
        error: Exception,
        *,
        retry_minutes: int = 5,
    ) -> None:
        conn = self._connection_factory()
        cur = self._cursor_factory(conn)
        try:
            cur.execute(self._sql("""
                UPDATE cron_task_ledger
                SET status = 'failed',
                    lease_expires_at = NULL,
                    next_retry_at = CURRENT_TIMESTAMP + (? * INTERVAL '1 minute'),
                    last_error = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE task_key = ?
                  AND scheduled_for = ?
                  AND status = 'running'
                  AND claim_token = ?
            """), (
                max(1, int(retry_minutes)),
                str(error)[:4000],
                task.key,
                task.scheduled_for,
                token,
            ))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            try:
                cur.close()
            finally:
                conn.close()


def execute_plan(ledger, tasks, handlers, *, now: datetime):
    """Esegue task isolati: un errore non impedisce i task successivi."""

    report = {"ok": True, "tasks": []}
    for task in tasks:
        token = ledger.claim(task, now=now)
        if token is None:
            report["tasks"].append({
                "task": task.key,
                "scheduled_for": task.scheduled_for.isoformat(),
                "status": "already_claimed_or_completed",
            })
            continue

        try:
            result = handlers[task.handler_name]()
            if isinstance(result, dict) and result.get("ok") is False:
                raise RuntimeError(
                    f"Task {task.key} non riuscito: "
                    f"{result.get('error') or result}"
                )
            ledger.complete(task, token, result)
            report["tasks"].append({
                "task": task.key,
                "scheduled_for": task.scheduled_for.isoformat(),
                "status": "completed",
                "result": result,
            })
        except Exception as error:
            report["ok"] = False
            try:
                ledger.fail(
                    task,
                    token,
                    error,
                    retry_minutes=task.retry_minutes,
                )
            except Exception as ledger_error:
                report["tasks"].append({
                    "task": task.key,
                    "scheduled_for": task.scheduled_for.isoformat(),
                    "status": "failed_and_ledger_update_failed",
                    "error": str(error),
                    "ledger_error": str(ledger_error),
                })
            else:
                report["tasks"].append({
                    "task": task.key,
                    "scheduled_for": task.scheduled_for.isoformat(),
                    "status": "failed",
                    "error": str(error),
                })
    return report


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return int(default)


def build_app_handlers(app_module):
    """Adatta i servizi applicativi al dispatcher senza route HTTP."""

    from accessi_utenti import elimina_accessi_scaduti
    from services import aggiorna_servizi_scaduti

    app = app_module.app

    def require_env(name):
        if not os.getenv(name, "").strip():
            raise RuntimeError(
                f"Variabile protetta {name} mancante sul cron consolidato; "
                "task non avviato."
            )

    def sync_services():
        return {"ok": True, "updated": aggiorna_servizi_scaduti()}

    def recover_reference_outbox():
        result = app_module.processa_referenze_notifiche_outbox_once()
        if isinstance(result, dict):
            return result
        return {"ok": True, "result": result}

    def chat_reminders():
        require_env("POSTMARK_SERVER_TOKEN")
        return app_module.processa_promemoria_email_chat(
            limite=max(1, min(_env_int("CHAT_EMAIL_REMINDER_BATCH_LIMIT", 10), 50))
        )

    def availability_daily():
        require_env("POSTMARK_SERVER_TOKEN")
        limit = max(1, _env_int("AVAILABILITY_REMINDER_BATCH_LIMIT", 100))
        reminders = app_module.processa_promemoria_disponibilita(
            limite=limit,
            dry_run=False,
        )
        lifecycle = app_module.processa_ciclo_disponibilita_annunci(
            limite=max(limit, 500),
            dry_run=False,
        )
        result = {
            "ok": bool(reminders.get("ok") and lifecycle.get("ok")),
            "promemoria": reminders,
            "ciclo_annunci": lifecycle,
        }

        conn = None
        try:
            conn = app_module.get_db_connection()
            result["accessi_eliminati"] = elimina_accessi_scaduti(
                conn,
                postgres=bool(app.config.get("IS_POSTGRES")),
            )
        except Exception as error:
            # Come nel runner precedente, la pulizia statistica non deve
            # annullare promemoria gia consegnati.
            result["accessi_eliminati"] = None
            result["accessi_cleanup_errore"] = str(error)
        finally:
            if conn is not None:
                conn.close()
        return result

    def incomplete_profiles():
        require_env("POSTMARK_SERVER_TOKEN")
        return app_module.invia_reminder_profili_incompleti(dry_run=False)

    def save_openai_usage():
        require_env("OPENAI_ADMIN_KEY")
        stats = app_module.get_openai_month_stats()
        if not stats.get("ok"):
            return stats
        app_module.salva_openai_usage_giornaliero(stats)
        return {
            "ok": True,
            "total_requests": stats.get("total_requests"),
            "total_cost": stats.get("total_cost_raw"),
        }

    return {
        "sync_servizi_scaduti": sync_services,
        "referenze_outbox_recovery": recover_reference_outbox,
        "chat_email_reminders": chat_reminders,
        "availability_daily": availability_daily,
        "incomplete_profiles_weekly": incomplete_profiles,
        "openai_monthly_save": save_openai_usage,
    }
