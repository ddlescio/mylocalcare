"""Esegue un batch degli avvisi progressivi sulla disponibilita.

Il processo e pensato per un cron/worker esterno. Impostando il ruolo ``job``
prima dell'import evitiamo di avviare i loop permanenti del servizio web.
"""

import argparse
import json
import os


os.environ.setdefault("RUNTIME_SERVICE", "job")


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return int(default)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Invia gli avvisi progressivi per la disponibilita servizi."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=_env_int("AVAILABILITY_REMINDER_BATCH_LIMIT", 100),
        help="Numero massimo di utenti da prenotare nel batch (default: 100).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=_env_bool("AVAILABILITY_REMINDER_DRY_RUN", False),
        help="Conta i destinatari senza aggiornare il DB o inviare messaggi.",
    )
    args = parser.parse_args(argv)

    from accessi_utenti import elimina_accessi_scaduti
    from app import (
        app,
        get_db_connection,
        processa_promemoria_disponibilita,
    )

    with app.app_context():
        result = processa_promemoria_disponibilita(
            limite=args.limit,
            dry_run=args.dry_run,
        )
        if not args.dry_run:
            conn = None
            try:
                conn = get_db_connection()
                result["accessi_eliminati"] = elimina_accessi_scaduti(conn)
            except Exception as exc:
                # Il promemoria principale non deve fallire se il deploy
                # precede la migrazione della tabella statistiche.
                result["accessi_eliminati"] = None
                result["accessi_cleanup_errore"] = str(exc)
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
