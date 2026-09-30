"""Coordinamento sicuro della pulizia delle videochiamate abbandonate.

Il lease Redis riduce il lavoro duplicato tra i processi permanenti. La vera
garanzia di unicita, tuttavia, resta l'UPDATE atomico con RETURNING: se Redis e
temporaneamente indisponibile, piu processi possono tentare la pulizia ma solo
quello che cambia davvero una riga riceve i dati necessari per notificare gli
utenti.
"""

from __future__ import annotations

import secrets
from typing import Any, Callable, Iterable


VIDEO_CLEANUP_LEASE_KEY = "lease:video_call_cleanup"
# Il lease resta vivo quasi quanto l'intervallo del loop (30 secondi). Non viene
# rilasciato dopo un giro riuscito: cosi gli altri worker non ripetono subito la
# stessa query. Se il vincitore muore, il TTL consente il subentro automatico.
VIDEO_CLEANUP_LEASE_SECONDS = 25

LEASE_ACQUIRED = "acquired"
LEASE_BUSY = "busy"
LEASE_UNAVAILABLE = "unavailable"


def video_cleanup_runtime_enabled(runtime_role: str | None) -> bool:
    """I loop permanenti appartengono solo ai processi web e realtime."""

    return str(runtime_role or "").strip().lower() in {"web", "realtime"}


def acquire_video_cleanup_lease(
    redis_client: Any,
    *,
    key: str = VIDEO_CLEANUP_LEASE_KEY,
    ttl_seconds: int = VIDEO_CLEANUP_LEASE_SECONDS,
    token_factory: Callable[[], str] | None = None,
) -> tuple[str, str | None]:
    """Prova a ottenere il lease, distinguendo contesa da Redis non disponibile."""

    token = (token_factory or (lambda: secrets.token_hex(16)))()
    try:
        acquired = bool(
            redis_client.set(
                key,
                token,
                nx=True,
                ex=max(1, int(ttl_seconds)),
            )
        )
    except Exception:
        # Fallback sicuro: l'UPDATE ... RETURNING resta idempotente e atomico.
        return LEASE_UNAVAILABLE, None

    if not acquired:
        return LEASE_BUSY, None
    return LEASE_ACQUIRED, token


def release_video_cleanup_lease(
    redis_client: Any,
    token: str | None,
    *,
    key: str = VIDEO_CLEANUP_LEASE_KEY,
) -> bool:
    """Rilascia il lease solo se appartiene ancora a questo processo."""

    if not token:
        return False

    try:
        released = redis_client.eval(
            """
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                return redis.call('DEL', KEYS[1])
            end
            return 0
            """,
            1,
            key,
            token,
        )
        return bool(released)
    except Exception:
        # Il TTL garantisce comunque il failover senza cancellare lease altrui.
        return False


def _row_value(row: Any, key: str, index: int) -> Any:
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return row[index]


def claim_stale_video_calls(
    connection: Any,
    *,
    cursor_factory: Callable[[Any], Any],
    sql_adapter: Callable[[str], str],
    stale_before_sql: str,
) -> list[Any]:
    """Chiude e restituisce in modo atomico soltanto le chiamate prese in carico."""

    cursor = cursor_factory(connection)
    try:
        cursor.execute(sql_adapter(f"""
            UPDATE video_call_log
            SET in_corso = 0,
                ended_at = CURRENT_TIMESTAMP
            WHERE in_corso = 1
              AND last_ping IS NOT NULL
              AND last_ping < {stale_before_sql}
            RETURNING id, room_name, utente_1, utente_2
        """))
        claimed = list(cursor.fetchall())
        connection.commit()
        return claimed
    except Exception:
        try:
            connection.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            cursor.close()
        except Exception:
            pass


def emit_video_cleanup_events(
    claimed_calls: Iterable[Any],
    *,
    emit: Callable[..., Any],
) -> int:
    """Emette lo sblocco soltanto per le righe vinte dall'UPDATE atomico."""

    emitted_calls = 0
    for call in claimed_calls:
        user_1 = _row_value(call, "utente_1", 2)
        user_2 = _row_value(call, "utente_2", 3)

        emit(
            "video_busy",
            {"user_id": user_1, "busy": False},
            room=f"user_{user_2}",
        )
        emit(
            "video_busy",
            {"user_id": user_2, "busy": False},
            room=f"user_{user_1}",
        )
        emitted_calls += 1

    return emitted_calls


def process_video_cleanup_once(
    *,
    redis_client: Any,
    connection_factory: Callable[[], Any],
    cursor_factory: Callable[[Any], Any],
    sql_adapter: Callable[[str], str],
    stale_before_sql: str,
    emit: Callable[..., Any],
) -> dict[str, Any]:
    """Esegue un giro coordinato e chiude sempre connessione e lease propri."""

    lease_status, lease_token = acquire_video_cleanup_lease(redis_client)
    if lease_status == LEASE_BUSY:
        return {
            "lease_status": lease_status,
            "claimed_count": 0,
            "emitted_count": 0,
        }

    connection = None
    completed = False
    try:
        connection = connection_factory()
        claimed = claim_stale_video_calls(
            connection,
            cursor_factory=cursor_factory,
            sql_adapter=sql_adapter,
            stale_before_sql=stale_before_sql,
        )
        emitted_count = emit_video_cleanup_events(claimed, emit=emit)
        result = {
            "lease_status": lease_status,
            "claimed_count": len(claimed),
            "emitted_count": emitted_count,
        }
        completed = True
        return result
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        # Dopo un giro riuscito il lease resta fino al TTL e funge anche da
        # throttle distribuito. In caso di errore lo liberiamo subito per
        # permettere a un altro processo permanente di ritentare.
        if lease_status == LEASE_ACQUIRED and not completed:
            release_video_cleanup_lease(redis_client, lease_token)
