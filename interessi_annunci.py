"""Operazioni atomiche sullo stato "Mi interessa" degli annunci."""

from datetime import datetime, timedelta, timezone


INTERESSE_NOTIFICATION_COOLDOWN = timedelta(hours=24)


def _timestamp_utc(value):
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def imposta_interesse_annuncio(
    conn,
    annuncio_id,
    utente_interessato_id,
    attivo,
    now=None,
):
    """Imposta uno stato esplicito e restituisce la transizione effettiva.

    L'UPSERT usa il vincolo univoco ``(annuncio_id,
    utente_interessato_id)``. La clausola ``WHERE`` evita che retry o doppi
    tap producano una seconda transizione. Il timestamp dell'ultima notifica
    viene prenotato nella stessa istruzione atomica solo quando il cooldown è
    scaduto.
    """

    annuncio_id = int(annuncio_id)
    utente_interessato_id = int(utente_interessato_id)

    if not isinstance(attivo, bool):
        raise TypeError("attivo deve essere un valore booleano")

    istante = _timestamp_utc(now or datetime.now(timezone.utc))
    marker = istante.isoformat(timespec="microseconds")
    cutoff = (
        istante - INTERESSE_NOTIFICATION_COOLDOWN
    ).isoformat(timespec="microseconds")

    cur = conn.cursor()

    try:
        if attivo:
            cur.execute(
                """
                INSERT INTO interessi_annunci (
                    annuncio_id,
                    utente_interessato_id,
                    attivo,
                    created_at,
                    updated_at,
                    disattivato_at,
                    ultima_notifica_at
                )
                VALUES (?, ?, ?, ?, ?, NULL, ?)
                ON CONFLICT (annuncio_id, utente_interessato_id)
                DO UPDATE SET
                    attivo = excluded.attivo,
                    updated_at = excluded.updated_at,
                    disattivato_at = NULL,
                    ultima_notifica_at = CASE
                        WHEN interessi_annunci.ultima_notifica_at IS NULL
                          OR interessi_annunci.ultima_notifica_at <= ?
                        THEN excluded.ultima_notifica_at
                        ELSE interessi_annunci.ultima_notifica_at
                    END
                WHERE interessi_annunci.attivo = ?
                RETURNING id, attivo, updated_at, ultima_notifica_at
                """,
                (
                    annuncio_id,
                    utente_interessato_id,
                    True,
                    marker,
                    marker,
                    marker,
                    cutoff,
                    False,
                ),
            )

            row = cur.fetchone()
            conn.commit()

            if not row:
                return {
                    "attivo": True,
                    "transizione": False,
                    "notifica": False,
                }

            updated_at = _timestamp_utc(row["updated_at"])
            ultima_notifica_at = _timestamp_utc(
                row["ultima_notifica_at"]
            )

            return {
                "attivo": True,
                "transizione": True,
                "notifica": (
                    updated_at == ultima_notifica_at == istante
                ),
            }

        cur.execute(
            """
            UPDATE interessi_annunci
            SET attivo = ?,
                updated_at = ?,
                disattivato_at = ?
            WHERE annuncio_id = ?
              AND utente_interessato_id = ?
              AND attivo = ?
            RETURNING id
            """,
            (
                False,
                marker,
                marker,
                annuncio_id,
                utente_interessato_id,
                True,
            ),
        )

        row = cur.fetchone()
        conn.commit()

        return {
            "attivo": False,
            "transizione": bool(row),
            "notifica": False,
        }

    finally:
        try:
            cur.close()
        except Exception:
            pass
