"""Pulizia transazionale dei dati delle referenze legati a un account.

Gli account LocalCare vengono anonimizzati invece di essere cancellati dalla
tabella ``utenti``.  Di conseguenza la FK ``referenze.utente_id`` non puo
attivare automaticamente ``ON DELETE CASCADE``.  Questo helper elimina prima
i dati figli sensibili e di audit e poi la referenza proprietaria, lasciando
al chiamante commit o rollback dell'intera cancellazione account.
"""

from __future__ import annotations

from typing import Any


_REFERENCE_TABLES = (
    "referenze",
    "referenze_contatti",
    "referenze_eventi",
)


def _row_value(row: Any, key: str, index: int = 0) -> Any:
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    if hasattr(row, "keys"):
        keys = list(row.keys())
        if key in keys:
            return row[key]
    return row[index]


def reference_tables_present(cursor, *, postgres: bool) -> set[str]:
    """Restituisce le tabelle referenze presenti durante un rollout.

    Il controllo e intenzionalmente granulare: se, per esempio, esiste la
    tabella principale ma una migrazione si e fermata prima di creare gli
    eventi, la cancellazione dell'account deve comunque purgare quanto esiste.
    """

    if postgres:
        cursor.execute("""
            SELECT
                to_regclass('public.referenze') AS referenze,
                to_regclass('public.referenze_contatti') AS referenze_contatti,
                to_regclass('public.referenze_eventi') AS referenze_eventi
        """)
        row = cursor.fetchone()
        return {
            table
            for index, table in enumerate(_REFERENCE_TABLES)
            if _row_value(row, table, index)
        }

    cursor.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name IN ('referenze', 'referenze_contatti', 'referenze_eventi')
    """)
    return {
        str(_row_value(row, "name"))
        for row in cursor.fetchall()
        if _row_value(row, "name")
    }


def purge_user_reference_data(
    cursor,
    user_id: int,
    *,
    postgres: bool,
) -> dict[str, int]:
    """Elimina tutti i dati referenze posseduti da ``user_id``.

    L'ordine esplicito non dipende dall'attivazione delle FK SQLite ne dalla
    correttezza di una vecchia installazione: vengono rimossi eventi/audit,
    recapiti cifrati, hash dei token e infine la riga che contiene testi e
    consensi.  Nessun commit viene eseguito, cosi un errore blocca e fa
    rollback insieme all'intera cancellazione account.
    """

    owner_id = int(user_id)
    tables = reference_tables_present(cursor, postgres=postgres)
    deleted = {
        "referenze_eventi": 0,
        "referenze_contatti": 0,
        "referenze": 0,
    }

    if "referenze" not in tables:
        return deleted

    for child_table in ("referenze_eventi", "referenze_contatti"):
        if child_table not in tables:
            continue
        cursor.execute(f"""
            DELETE FROM {child_table}
            WHERE referenza_id IN (
                SELECT id
                FROM referenze
                WHERE utente_id = ?
            )
        """, (owner_id,))
        deleted[child_table] = max(int(cursor.rowcount or 0), 0)

    cursor.execute("""
        DELETE FROM referenze
        WHERE utente_id = ?
    """, (owner_id,))
    deleted["referenze"] = max(int(cursor.rowcount or 0), 0)
    return deleted
