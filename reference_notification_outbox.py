"""Outbox persistente per le notifiche generate dalle referenze.

Il submit pubblico scrive soltanto righe DB nella stessa transazione della
referenza.  Il worker crea poi la notifica interna e, quando richiesto, invia
la push.  Ogni fase e' persistente: un riavvio puo' riprendere il lavoro senza
duplicare la notifica interna.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid


DEFAULT_LEASE_SECONDS = 300
DEFAULT_RETRY_BASE_SECONDS = 5
DEFAULT_RETRY_MAX_SECONDS = 900


def _row_dict(row):
    if row is None:
        return None
    return dict(row)


def _utcnow(now=None):
    value = now() if callable(now) else now
    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value):
    return value.isoformat()


def enqueue_reference_response_notifications(
    cursor,
    sql,
    *,
    reference_id,
    reference_version,
    owner_id,
    owner_title,
    owner_message,
    owner_link,
    direct,
    admin_title,
    admin_message,
    admin_link,
):
    """Accoda destinatari owner/admin senza eseguire I/O esterno.

    ``event_key`` rende l'operazione idempotente anche se il chiamante ripete
    l'INSERT nella stessa transazione o un retry applicativo rilegge la stessa
    versione della referenza.
    """

    deliveries = [(
        int(owner_id),
        "owner",
        str(owner_title),
        str(owner_message),
        "profilo",
        str(owner_link),
        False,
    )]

    if direct:
        cursor.execute(sql("""
            SELECT id
            FROM utenti
            WHERE ruolo = 'admin'
              AND attivo = 1
              AND sospeso = 0
              AND COALESCE(disattivato_admin, 0) = 0
            ORDER BY id
        """))
        deliveries.extend((
            int(admin["id"]),
            "admin",
            str(admin_title),
            str(admin_message),
            "admin",
            str(admin_link),
            True,
        ) for admin in cursor.fetchall())

    inserted = 0
    for (
        recipient_id,
        recipient_kind,
        title,
        message,
        notification_type,
        link,
        push_required,
    ) in deliveries:
        event_key = (
            f"reference-response:{int(reference_id)}:"
            f"v{int(reference_version)}:{recipient_kind}:{recipient_id}"
        )
        cursor.execute(sql("""
            INSERT INTO referenze_notifiche_outbox (
                event_key,
                referenza_id,
                destinatario_id,
                destinatario_tipo,
                titolo,
                messaggio,
                tipo_notifica,
                link,
                push_richiesta,
                disponibile_at,
                created_at,
                updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            ON CONFLICT (event_key) DO NOTHING
        """), (
            event_key,
            int(reference_id),
            recipient_id,
            recipient_kind,
            title,
            message,
            notification_type,
            link,
            bool(push_required),
        ))
        inserted += max(int(cursor.rowcount or 0), 0)

    return inserted


def _begin(cursor, sql, is_postgres):
    cursor.execute(sql("BEGIN" if is_postgres else "BEGIN IMMEDIATE"))


def _commit(cursor, sql):
    cursor.execute(sql("COMMIT"))


def _rollback(cursor, sql):
    try:
        cursor.execute(sql("ROLLBACK"))
    except Exception:
        pass


def _close(cursor=None, connection=None):
    if cursor is not None:
        try:
            cursor.close()
        except Exception:
            pass
    if connection is not None:
        try:
            connection.close()
        except Exception:
            pass


def _claim_due(
    *,
    connect,
    cursor_factory,
    sql,
    is_postgres,
    limit,
    now,
    lease_seconds,
):
    connection = connect()
    cursor = cursor_factory(connection)
    claimed = []
    current = _utcnow(now)
    current_iso = _iso(current)
    expired_iso = _iso(current - timedelta(seconds=int(lease_seconds)))
    lock_suffix = " FOR UPDATE SKIP LOCKED" if is_postgres else ""

    try:
        _begin(cursor, sql, is_postgres)
        cursor.execute(sql(f"""
            SELECT *
            FROM referenze_notifiche_outbox
            WHERE elaborata_at IS NULL
              AND disponibile_at <= ?
              AND (
                    bloccata_at IS NULL
                    OR bloccata_at < ?
              )
            ORDER BY disponibile_at ASC, id ASC
            LIMIT ?{lock_suffix}
        """), (current_iso, expired_iso, int(limit)))
        rows = [_row_dict(row) for row in cursor.fetchall()]

        for row in rows:
            token = uuid.uuid4().hex
            cursor.execute(sql("""
                UPDATE referenze_notifiche_outbox
                SET bloccata_at = ?, blocco_token = ?,
                    tentativi = tentativi + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND elaborata_at IS NULL
                  AND (
                        bloccata_at IS NULL
                        OR bloccata_at < ?
                  )
            """), (current_iso, token, int(row["id"]), expired_iso))
            if cursor.rowcount != 1:
                continue
            row["blocco_token"] = token
            row["tentativi"] = int(row.get("tentativi") or 0) + 1
            claimed.append(row)

        _commit(cursor, sql)
        return claimed
    except Exception:
        _rollback(cursor, sql)
        raise
    finally:
        _close(cursor, connection)


def _ensure_internal_notification(
    delivery,
    *,
    connect,
    cursor_factory,
    sql,
    is_postgres,
):
    connection = connect()
    cursor = cursor_factory(connection)
    lock_suffix = " FOR UPDATE" if is_postgres else ""
    try:
        _begin(cursor, sql, is_postgres)
        cursor.execute(sql(f"""
            SELECT id, notifica_creata_at
            FROM referenze_notifiche_outbox
            WHERE id = ? AND blocco_token = ? AND elaborata_at IS NULL
            LIMIT 1{lock_suffix}
        """), (int(delivery["id"]), delivery["blocco_token"]))
        current = cursor.fetchone()
        if not current:
            _rollback(cursor, sql)
            return False

        current = _row_dict(current)
        if not current.get("notifica_creata_at"):
            cursor.execute(sql("""
                INSERT INTO notifiche (
                    id_utente, titolo, messaggio, tipo, link, letta
                ) VALUES (?, ?, ?, ?, ?, 0)
            """), (
                int(delivery["destinatario_id"]),
                delivery["titolo"],
                delivery["messaggio"],
                delivery["tipo_notifica"],
                delivery.get("link"),
            ))
            cursor.execute(sql("""
                UPDATE referenze_notifiche_outbox
                SET notifica_creata_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND blocco_token = ?
                  AND notifica_creata_at IS NULL
            """), (int(delivery["id"]), delivery["blocco_token"]))

        _commit(cursor, sql)
        return True
    except Exception:
        _rollback(cursor, sql)
        raise
    finally:
        _close(cursor, connection)


def _mark_processed(
    delivery,
    *,
    connect,
    cursor_factory,
    sql,
):
    connection = connect()
    cursor = cursor_factory(connection)
    try:
        cursor.execute(sql("""
            UPDATE referenze_notifiche_outbox
            SET elaborata_at = CURRENT_TIMESTAMP,
                bloccata_at = NULL,
                blocco_token = NULL,
                ultimo_errore = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND blocco_token = ? AND elaborata_at IS NULL
        """), (int(delivery["id"]), delivery["blocco_token"]))
        connection.commit()
        return cursor.rowcount == 1
    finally:
        _close(cursor, connection)


def _release_for_retry(
    delivery,
    error,
    *,
    connect,
    cursor_factory,
    sql,
    now,
    retry_base_seconds,
    retry_max_seconds,
):
    attempts = max(int(delivery.get("tentativi") or 1), 1)
    delay = min(
        int(retry_max_seconds),
        int(retry_base_seconds) * (2 ** min(attempts - 1, 16)),
    )
    available = _iso(_utcnow(now) + timedelta(seconds=delay))
    error_text = f"{type(error).__name__}: {error}"[:1000]
    connection = connect()
    cursor = cursor_factory(connection)
    try:
        cursor.execute(sql("""
            UPDATE referenze_notifiche_outbox
            SET disponibile_at = ?,
                bloccata_at = NULL,
                blocco_token = NULL,
                ultimo_errore = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND blocco_token = ? AND elaborata_at IS NULL
        """), (
            available,
            error_text,
            int(delivery["id"]),
            delivery["blocco_token"],
        ))
        connection.commit()
    finally:
        _close(cursor, connection)


def process_reference_notification_outbox_once(
    *,
    connect,
    cursor_factory,
    sql,
    is_postgres,
    send_push,
    emit_realtime,
    limit=20,
    now=None,
    lease_seconds=DEFAULT_LEASE_SECONDS,
    retry_base_seconds=DEFAULT_RETRY_BASE_SECONDS,
    retry_max_seconds=DEFAULT_RETRY_MAX_SECONDS,
    log_error=None,
):
    """Elabora un batch usando connessioni proprie e retry persistente."""

    deliveries = _claim_due(
        connect=connect,
        cursor_factory=cursor_factory,
        sql=sql,
        is_postgres=bool(is_postgres),
        limit=max(int(limit), 1),
        now=now,
        lease_seconds=max(int(lease_seconds), 1),
    )
    result = {"claimed": len(deliveries), "processed": 0, "retried": 0}

    for delivery in deliveries:
        try:
            owns_lease = _ensure_internal_notification(
                delivery,
                connect=connect,
                cursor_factory=cursor_factory,
                sql=sql,
                is_postgres=bool(is_postgres),
            )
            if not owns_lease:
                continue

            if bool(delivery.get("push_richiesta")):
                push_result = send_push(
                    int(delivery["destinatario_id"]),
                    delivery["titolo"],
                    delivery["messaggio"],
                    delivery.get("link"),
                )
                if push_result is False:
                    raise RuntimeError("push delivery failed")

            # Il realtime non decide l'esito: viene tentato solo dopo che la
            # notifica interna e l'eventuale push sono state completate.
            try:
                emit_realtime(
                    int(delivery["destinatario_id"]),
                    delivery["destinatario_tipo"],
                )
            except Exception as realtime_error:
                if log_error:
                    log_error("reference outbox realtime best-effort", realtime_error)

            if _mark_processed(
                delivery,
                connect=connect,
                cursor_factory=cursor_factory,
                sql=sql,
            ):
                result["processed"] += 1
        except Exception as error:
            _release_for_retry(
                delivery,
                error,
                connect=connect,
                cursor_factory=cursor_factory,
                sql=sql,
                now=now,
                retry_base_seconds=max(int(retry_base_seconds), 1),
                retry_max_seconds=max(int(retry_max_seconds), 1),
            )
            result["retried"] += 1
            if log_error:
                log_error("reference notification outbox retry", error)

    return result
