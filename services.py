from typing import Optional, Dict, Any, List, Tuple

def get_db_connection():
    from app import get_db_connection as _f
    return _f()

def get_cursor(conn):
    from app import get_cursor as _f
    return _f(conn)

def sql(query):
    from app import sql as _f
    return _f(query)

def is_postgres():
    from flask import current_app
    return current_app.config.get("IS_POSTGRES", False)
    
def now_sql():
    return "CURRENT_TIMESTAMP" if is_postgres() else "datetime('now')"

def dt_sql(field):
    from app import dt_sql as _f
    return _f(field)
# ---------------------------------------------------------
# Normalizzazione codici servizio (alias)
# ---------------------------------------------------------

SERVICE_ALIAS = {
    "contatti": "contatti",              # servizio attuale
    "contatti_profilo": "contatti",       # alias futuro/compatibilità
}
def _normalize_codice_servizio(codice: str) -> str:
    codice = (codice or "").strip().lower()
    return SERVICE_ALIAS.get(codice, codice)

# =========================================================
# SERVIZI / ATTIVAZIONI - CORE ENGINE (STEP 3A)
# =========================================================

def _fetchone(conn, query: str, params: tuple = ()) -> Optional[dict]:
    cur = get_cursor(conn)
    cur.execute(sql(query), params)   # <-- QUI
    return cur.fetchone()

def _fetchall(conn, query: str, params: tuple = ()) -> List[dict]:
    cur = get_cursor(conn)
    cur.execute(sql(query), params)   # <-- QUI
    return cur.fetchall()

def _now_sql() -> str:
    return now_sql()

def _add_days_sql(days: int) -> str:
    days = int(days)
    if is_postgres():
        return f"{_now_sql()} + INTERVAL '{days} days'"
    return f"datetime('now','+{days} days')"

def _extend_from_current_or_end_sql(days: int) -> str:
    days = int(days)

    if is_postgres():
        return f"(CASE WHEN {dt_sql('data_fine')} > {_now_sql()} THEN {dt_sql('data_fine')} ELSE {_now_sql()} END) + INTERVAL '{days} days'"

    # SQLite
    return f"datetime(CASE WHEN data_fine > {_now_sql()} THEN data_fine ELSE {_now_sql()} END, '+{days} days')"

def _to_int_bool(v: Any) -> int:
    try:
        return 1 if int(v) == 1 else 0
    except Exception:
        return 0

def servizio_attivo_per_utente(utente_id: int, codice_servizio: str, conn=None) -> bool:
    """
    True se l'utente ha una attivazione attiva (non scaduta) per quel servizio.
    """
    codice_servizio = _normalize_codice_servizio(codice_servizio)
    if conn is None:
        conn = get_db_connection()

    row = _fetchone(conn, f"""
        SELECT 1
        FROM attivazioni_servizi a
        JOIN servizi s ON s.id = a.servizio_id
        WHERE a.utente_id = ?
          AND s.codice = ?
          AND a.stato = 'attivo'
          AND {dt_sql("a.data_inizio")} <= {_now_sql()}
          AND (a.data_fine IS NULL OR {dt_sql("a.data_fine")} > {_now_sql()})
        LIMIT 1
    """, (utente_id, codice_servizio))


    return row is not None


def servizio_attivo_per_annuncio(annuncio_id: int, codice_servizio: str, conn=None) -> bool:
    """
    True se l'annuncio ha una attivazione attiva (non scaduta) per quel servizio.
    """
    codice_servizio = _normalize_codice_servizio(codice_servizio)
    if conn is None:
        conn = get_db_connection()

    row = _fetchone(conn, f"""
        SELECT 1
        FROM attivazioni_servizi a
        JOIN servizi s ON s.id = a.servizio_id
        WHERE a.annuncio_id = ?
          AND s.codice = ?
          AND a.stato = 'attivo'
          AND {dt_sql("a.data_inizio")} <= {_now_sql()}
          AND (a.data_fine IS NULL OR {dt_sql("a.data_fine")} > {_now_sql()})
        LIMIT 1
    """, (annuncio_id, codice_servizio))


    return row is not None


def get_servizi_attivi_utente(utente_id: int, conn=None) -> List[Dict[str, Any]]:
    """
    Ritorna la lista dei servizi attivi per utente (utile per debug/pannello).
    """
    if conn is None:
        conn = get_db_connection()

    rows = _fetchall(conn, f"""
        SELECT
            a.id AS attivazione_id,
            s.codice,
            s.nome,
            s.ambito,
            s.target,
            a.annuncio_id,
            a.data_inizio,
            a.data_fine,
            a.stato,
            a.attivato_da
        FROM attivazioni_servizi a
        JOIN servizi s ON s.id = a.servizio_id
        WHERE a.utente_id = ?
          AND a.stato = 'attivo'
          AND {dt_sql("a.data_inizio")} <= {_now_sql()}
          AND (a.data_fine IS NULL OR {dt_sql("a.data_fine")} > {_now_sql()})
        ORDER BY a.data_inizio DESC
    """, (utente_id,))


    return [dict(r) for r in rows]


def get_servizi_attivi_annuncio(annuncio_id: int, conn=None) -> List[Dict[str, Any]]:
    """
    Ritorna la lista dei servizi attivi per annuncio (utile per debug/pannello).
    """
    if conn is None:
        conn = get_db_connection()

    rows = _fetchall(conn, f"""
        SELECT
            a.id AS attivazione_id,
            s.codice,
            s.nome,
            s.ambito,
            s.target,
            a.data_inizio,
            a.data_fine,
            a.stato,
            a.attivato_da
        FROM attivazioni_servizi a
        JOIN servizi s ON s.id = a.servizio_id
        WHERE a.annuncio_id = ?
          AND a.stato = 'attivo'
          AND {dt_sql("a.data_inizio")} <= {_now_sql()}
          AND (a.data_fine IS NULL OR {dt_sql("a.data_fine")} > {_now_sql()})
        ORDER BY a.data_inizio DESC
    """, (annuncio_id,))


    return [dict(r) for r in rows]


def aggiorna_servizi_scaduti() -> int:
    """
    Marca come 'scaduto' le attivazioni che hanno superato data_fine.
    Ritorna quante righe sono state aggiornate.
    """
    conn = get_db_connection()

    cur = get_cursor(conn)

    cur.execute(sql(f"""
        UPDATE attivazioni_servizi
        SET stato = 'scaduto'
        WHERE stato = 'attivo'
          AND data_fine IS NOT NULL
          AND {dt_sql("data_fine")} <= {_now_sql()}
    """))

    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated

# ---------------------------------------------------------
# PUNTEGGIO / PRIORITÀ (base) - la useremo nello STEP 3B
# ---------------------------------------------------------

# Codici esempio (li definiremo nella tabella servizi):
COD_BOOST_LISTA = "boost_lista"
COD_VETRINA = "vetrina_annuncio"
COD_CONTATTI_ANNUNCIO = "contatti_annuncio"
COD_CONTATTI_PROFILO = "contatti_profilo"

def get_peso_annuncio(annuncio_id: int) -> int:
    """
    Peso ranking annuncio (lista).
    - boost_lista = +100
    - NESSUN altro servizio influisce sul ranking
    """
    peso = 0

    if servizio_attivo_per_annuncio(annuncio_id, COD_BOOST_LISTA):
        peso += 100

    return peso
# ---------------------------------------------------------
# Storico
# ---------------------------------------------------------
def _storico_append(conn, attivazione_id: int, azione: str, eseguito_da: str, note: str = "") -> None:
    cur = get_cursor(conn)
    cur.execute(sql("""
        INSERT INTO storico_servizi (attivazione_id, azione, eseguito_da, note)
        VALUES (?, ?, ?, ?)
    """), (attivazione_id, azione, eseguito_da, note or ""))
# ---------------------------------------------------------
# Query di utilità
# ---------------------------------------------------------
def _get_servizio_by_codice(conn, codice_servizio: str) -> Optional[dict]:
    return _fetchone(conn, """
        SELECT id, codice, nome, descrizione, ambito, target,
               durata_default_giorni, ripetibile, attivabile_admin, attivo
        FROM servizi
        WHERE codice = ?
        LIMIT 1
    """, (codice_servizio,))

def _get_active_activation(conn, utente_id: int, servizio_id: int, annuncio_id: Optional[int]) -> Optional[dict]:
    # se annuncio_id è NULL, cerchiamo attivazioni globali/profilo (annuncio_id IS NULL)
    if annuncio_id is None:
        return _fetchone(conn, f"""
            SELECT id, data_inizio, data_fine, stato
            FROM attivazioni_servizi
            WHERE utente_id = ?
              AND servizio_id = ?
              AND annuncio_id IS NULL
              AND stato = 'attivo'
              AND {dt_sql("data_inizio")} <= {_now_sql()}
              AND (data_fine IS NULL OR {dt_sql("data_fine")} > {_now_sql()})
            LIMIT 1
        """, (utente_id, servizio_id))
    else:
        return _fetchone(conn, f"""
            SELECT id, data_inizio, data_fine, stato
            FROM attivazioni_servizi
            WHERE utente_id = ?
              AND servizio_id = ?
              AND annuncio_id = ?
              AND stato = 'attivo'
              AND {dt_sql("data_inizio")} <= {_now_sql()}
              AND (data_fine IS NULL OR {dt_sql("data_fine")} > {_now_sql()})
            LIMIT 1
        """, (utente_id, servizio_id, annuncio_id))


def _validate_annuncio_owner(conn, annuncio_id: int, utente_id: int) -> bool:
    row = _fetchone(conn, "SELECT 1 FROM annunci WHERE id = ? AND utente_id = ? LIMIT 1", (annuncio_id, utente_id))
    return row is not None


# ---------------------------------------------------------
# ✅ FUNZIONE A: attiva_servizio(...)
# ---------------------------------------------------------
def attiva_servizio(
    utente_id: int,
    codice_servizio: Optional[str] = None,
    servizio_id: Optional[int] = None,
    annuncio_id: Optional[int] = None,
    durata_giorni: Optional[int] = None,
    acquisto_id: Optional[int] = None,
    attivato_da: str = "utente",
    note: str = "",
    conn: Optional[Any] = None
) -> Tuple[bool, str, Optional[int]]:

    if attivato_da not in ("utente", "admin", "sistema", "stripe"):
        return False, "attivato_da non valido.", None

    own_conn = False
    if conn is None:
        conn = get_db_connection()
        own_conn = True

    cur = get_cursor(conn)

    try:
        # -------------------------------
        # 1️⃣ RECUPERO SERVIZIO
        # -------------------------------
        if servizio_id is not None:
            s = _fetchone(conn, """
                SELECT id, codice, ambito, durata_default_giorni,
                       ripetibile, attivabile_admin, attivo
                FROM servizi
                WHERE id = ?
            """, (int(servizio_id),))
        else:
            if not codice_servizio:
                return False, "codice_servizio o servizio_id obbligatorio.", None
            codice_servizio = _normalize_codice_servizio(codice_servizio)
            s = _get_servizio_by_codice(conn, codice_servizio)

        if not s:
            return False, "Servizio non trovato.", None
        if _to_int_bool(s["attivo"]) != 1:
            return False, "Servizio disattivato.", None

        ambito = (s["ambito"] or "").lower()

        if ambito == "annuncio":
            if annuncio_id is None:
                return False, "annuncio_id obbligatorio.", None
            if not _validate_annuncio_owner(conn, int(annuncio_id), utente_id):
                return False, "Annuncio non valido.", None
        else:
            annuncio_id = None

        durata_finale = durata_giorni if durata_giorni is not None else s["durata_default_giorni"]

        if durata_finale is not None:
            durata_finale = int(durata_finale)
            if durata_finale <= 0:
                return False, "Durata non valida.", None

        # -------------------------------
        # 2️⃣ ULTIMA ATTIVAZIONE
        # -------------------------------
        if annuncio_id is None:
            last = _fetchone(conn, """
                SELECT *
                FROM attivazioni_servizi
                WHERE utente_id = ?
                  AND servizio_id = ?
                  AND annuncio_id IS NULL
                ORDER BY id DESC
                LIMIT 1
            """, (utente_id, s["id"]))
        else:
            last = _fetchone(conn, """
                SELECT *
                FROM attivazioni_servizi
                WHERE utente_id = ?
                  AND servizio_id = ?
                  AND annuncio_id = ?
                ORDER BY id DESC
                LIMIT 1
            """, (utente_id, s["id"], annuncio_id))

        # -------------------------------
        # 🔁 RINNOVO
        # -------------------------------
        if last and last["stato"] == "attivo":

            if last["data_fine"] is None:
                return False, "Servizio già attivo senza scadenza.", None

            if durata_finale is None:
                return False, "Servizio già attivo.", None

            cur.execute(sql(f"""
                UPDATE attivazioni_servizi
                SET data_fine = {_extend_from_current_or_end_sql(durata_finale)}
                WHERE id = ?
            """), (last["id"],))

            _storico_append(conn, last["id"], "rinnovato", attivato_da, note or "")

            if own_conn:
                conn.commit()

            return True, "Servizio rinnovato.", int(last["id"])

        # -------------------------------
        # 🆕 NUOVA ATTIVAZIONE
        # -------------------------------
        if durata_finale is None:

            cur.execute(sql(f"""
                INSERT INTO attivazioni_servizi
                (acquisto_id, servizio_id, utente_id, annuncio_id,
                 data_inizio, data_fine, stato, attivato_da)
                VALUES (?, ?, ?, ?, {_now_sql()}, NULL, 'attivo', ?)
            """), (acquisto_id, s["id"], utente_id, annuncio_id, attivato_da))

        else:

            cur.execute(sql(f"""
                INSERT INTO attivazioni_servizi
                (acquisto_id, servizio_id, utente_id, annuncio_id,
                 data_inizio, data_fine, stato, attivato_da)
                VALUES (?, ?, ?, ?, {_now_sql()},
                        {_add_days_sql(durata_finale)},
                        'attivo', ?)
            """), (acquisto_id, s["id"], utente_id, annuncio_id, attivato_da))

        # -------------------------------
        # 🔑 RECUPERO ID INSERITO
        # -------------------------------
        if is_postgres():
            cur.execute(sql("SELECT currval(pg_get_serial_sequence('attivazioni_servizi','id'))"))
            att_id = cur.fetchone()["currval"]
        else:
            cur.execute(sql("SELECT last_insert_rowid()"))
            att_id = cur.fetchone()[0]

        _storico_append(conn, att_id, "creato", attivato_da, note or "")

        if own_conn:
            conn.commit()

        return True, "Servizio attivato.", int(att_id)

    except Exception as e:
        if own_conn:
            conn.rollback()
        return False, f"Errore attivazione servizio: {e}", None

    finally:
        if own_conn:
            conn.close()
# ---------------------------------------------------------
# (opzionale ma utile) Revoca forzata
# ---------------------------------------------------------
def revoca_attivazione(attivazione_id: int, eseguito_da: str = "admin", note: str = "") -> Tuple[bool, str]:
    conn = get_db_connection()

    try:
        row = _fetchone(conn, "SELECT stato FROM attivazioni_servizi WHERE id = ? LIMIT 1", (attivazione_id,))
        if not row:
            return False, "Attivazione non trovata."
        if row["stato"] != "attivo":
            return False, "Attivazione non è in stato attivo."

        cur = get_cursor(conn)
        cur.execute(sql("""
            UPDATE attivazioni_servizi
            SET stato='revocato'
            WHERE id = ?
        """), (attivazione_id,))
        _storico_append(conn, attivazione_id, "revocato", eseguito_da, note or "")
        conn.commit()
        return True, "Attivazione revocata."
    except Exception as e:
        conn.rollback()
        return False, f"Errore revoca: {e}"
    finally:
        conn.close()

def get_boost_score_sql() -> str:
    """
    Ritorna una sotto-espressione SQL che calcola un punteggio per annuncio
    basato sui servizi attivi.
    (Per ora solo boost_lista; estendibile)
    """
    return f"""
    (
      SELECT
        COALESCE(SUM(
          CASE
            WHEN s.codice = 'boost_lista' THEN 100
            ELSE 0
          END
        ), 0)
      FROM attivazioni_servizi a
      JOIN servizi s ON s.id = a.servizio_id
      WHERE a.annuncio_id = annunci.id
        AND a.stato = 'attivo'
        AND {dt_sql("a.data_inizio")} <= {_now_sql()}
        AND (a.data_fine IS NULL OR {dt_sql("a.data_fine")} > {_now_sql()})
    )
    """

def get_servizio_con_piani(codice_servizio: str, conn=None):
    """
    Ritorna:
    {
      servizio: {...},
      piani: [{...}, {...}, {...}]
    }
    oppure None se servizio non valido / non attivo
    """

    own_conn = False
    if conn is None:
        conn = get_db_connection()
        own_conn = True
    cur = get_cursor(conn)

    # 1️⃣ servizio
    cur.execute(sql("""
        SELECT
            id,
            codice,
            nome,
            descrizione,
            ambito,
            target
        FROM servizi
        WHERE codice = ?
          AND attivo = 1
        LIMIT 1
    """), (codice_servizio,))
    servizio = cur.fetchone()

    if not servizio:
        if own_conn:
            conn.close()
        return None

    # 2️⃣ piani attivi (popcorn 🍿)
    cur.execute(sql("""
        SELECT
            id,
            codice,
            nome,
            descrizione,
            durata_giorni,
            prezzo_cent,
            ordine,
            evidenziato,
            consigliato
        FROM servizi_piani
        WHERE servizio_id = ?
          AND attivo = 1
        ORDER BY ordine ASC, durata_giorni ASC
    """), (servizio["id"],))
    piani = cur.fetchall()



    result = {
        "servizio": dict(servizio),
        "piani": [dict(p) for p in piani]
    }

    if own_conn:
        conn.close()

    return result
