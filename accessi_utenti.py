"""Statistiche minimali di utilizzo di MyLocalCare.

Per gli account registra al massimo una riga per utente e giorno. Per i
visitatori anonimi conserva soltanto un totale giornaliero aggregato, contando
al massimo una visita per sessione e giorno tramite la sessione tecnica già in
uso. Non salva IP, user agent, URL visitati o identificatori anonimi nel DB.
"""

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo


ACCESS_WINDOW_DAYS = 30
ACCESS_TIMEZONE = ZoneInfo("Europe/Rome")


def giorno_locale(value=None):
    """Restituisce il giorno corrente nel fuso italiano."""

    if value is None:
        value = datetime.now(ACCESS_TIMEZONE)

    if isinstance(value, date) and not isinstance(value, datetime):
        return value

    if value.tzinfo is None:
        value = value.replace(tzinfo=ACCESS_TIMEZONE)

    return value.astimezone(ACCESS_TIMEZONE).date()


def normalizza_zona(*valori):
    """Sceglie la prima zona valorizzata senza esporre indirizzi puntuali."""

    for valore in valori:
        testo = str(valore or "").strip()
        if testo:
            return testo[:120]
    return "Zona non indicata"


def _timestamp_locale(value=None):
    if value is None:
        value = datetime.now(ACCESS_TIMEZONE)
    elif value.tzinfo is None:
        value = value.replace(tzinfo=ACCESS_TIMEZONE)
    else:
        value = value.astimezone(ACCESS_TIMEZONE)
    return value.isoformat(timespec="seconds")


def _row_value(row, key, index):
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return row[index]


def _table_exists(cur, table_name, *, postgres=False):
    """Controllo allowlist-safe usato durante deploy parziali."""

    allowed = {
        "accessi_utenti_giornalieri",
        "accessi_anonimi_giornalieri",
    }
    if table_name not in allowed:
        raise ValueError("Tabella statistiche non consentita")

    if postgres:
        cur.execute(
            f"SELECT to_regclass('public.{table_name}') AS tabella"
        )
        row = cur.fetchone()
        return bool(_row_value(row, "tabella", 0)) if row else False

    cur.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        LIMIT 1
        """,
        (table_name,),
    )
    return cur.fetchone() is not None


def registra_accesso_giornaliero(
    conn,
    *,
    utente_id,
    zona,
    giorno=None,
    istante=None,
):
    """Registra un utente una sola volta al giorno e applica la retention."""

    giorno = giorno_locale(giorno or istante)
    zona = normalizza_zona(zona)
    timestamp = _timestamp_locale(istante)
    inizio_finestra = giorno - timedelta(days=ACCESS_WINDOW_DAYS - 1)

    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO accessi_utenti_giornalieri (
                utente_id,
                giorno,
                zona,
                primo_accesso_at,
                ultimo_accesso_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (utente_id, giorno)
            DO UPDATE SET
                zona = CASE
                    WHEN excluded.zona <> 'Zona non indicata'
                    THEN excluded.zona
                    ELSE accessi_utenti_giornalieri.zona
                END,
                ultimo_accesso_at = excluded.ultimo_accesso_at
            """,
            (
                int(utente_id),
                giorno.isoformat(),
                zona,
                timestamp,
                timestamp,
            ),
        )
        cur.execute(
            """
            DELETE FROM accessi_utenti_giornalieri
            WHERE giorno < ?
            """,
            (inizio_finestra.isoformat(),),
        )
        conn.commit()
    finally:
        try:
            cur.close()
        except Exception:
            pass

    return giorno


def registra_visita_anonima_giornaliera(
    conn,
    *,
    giorno=None,
    istante=None,
):
    """Incrementa un totale aggregato; nessun visitatore viene identificato."""

    giorno = giorno_locale(giorno or istante)
    timestamp = _timestamp_locale(istante)
    inizio_finestra = giorno - timedelta(days=ACCESS_WINDOW_DAYS - 1)

    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO accessi_anonimi_giornalieri (
                giorno,
                visite_sessione,
                primo_accesso_at,
                ultimo_accesso_at
            )
            VALUES (?, 1, ?, ?)
            ON CONFLICT (giorno)
            DO UPDATE SET
                visite_sessione =
                    accessi_anonimi_giornalieri.visite_sessione + 1,
                ultimo_accesso_at = excluded.ultimo_accesso_at
            """,
            (giorno.isoformat(), timestamp, timestamp),
        )
        cur.execute(
            """
            DELETE FROM accessi_anonimi_giornalieri
            WHERE giorno < ?
            """,
            (inizio_finestra.isoformat(),),
        )
        conn.commit()
    finally:
        try:
            cur.close()
        except Exception:
            pass

    return giorno


def elimina_accessi_scaduti(conn, *, giorno=None, postgres=False):
    """Elimina definitivamente gli accessi fuori dalla finestra di 30 giorni."""

    giorno = giorno_locale(giorno)
    inizio_finestra = giorno - timedelta(days=ACCESS_WINDOW_DAYS - 1)
    cur = conn.cursor()
    try:
        eliminati = 0
        for table_name in (
            "accessi_utenti_giornalieri",
            "accessi_anonimi_giornalieri",
        ):
            if not _table_exists(cur, table_name, postgres=postgres):
                continue
            cur.execute(
                f"DELETE FROM {table_name} WHERE giorno < ?",
                (inizio_finestra.isoformat(),),
            )
            eliminati += max(int(cur.rowcount or 0), 0)
        conn.commit()
        return eliminati
    finally:
        try:
            cur.close()
        except Exception:
            pass


def elimina_accessi_utente(cur, utente_id, *, postgres=False):
    """Rimuove le presenze di un account senza dipendere dalla FK cascade.

    MyLocalCare anonimizza la riga ``utenti`` invece di eliminarla, quindi la
    pulizia deve essere esplicita. Il controllo preventivo rende il passaggio
    sicuro anche durante il breve rollout precedente alla migrazione.
    """

    presente = _table_exists(
        cur,
        "accessi_utenti_giornalieri",
        postgres=postgres,
    )

    if not presente:
        return 0

    cur.execute(
        "DELETE FROM accessi_utenti_giornalieri WHERE utente_id = ?",
        (int(utente_id),),
    )
    return max(int(cur.rowcount or 0), 0)


def _parse_day(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def carica_statistiche_accessi(conn, *, giorno=None, postgres=False):
    """Calcola riepilogo, serie mensile e distribuzione geografica."""

    giorno = giorno_locale(giorno)
    inizio_mese = giorno - timedelta(days=ACCESS_WINDOW_DAYS - 1)
    inizio_settimana = giorno - timedelta(days=6)

    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT giorno, utente_id, zona
            FROM accessi_utenti_giornalieri
            WHERE giorno >= ?
              AND giorno <= ?
            ORDER BY giorno ASC, utente_id ASC
            """,
            (inizio_mese.isoformat(), giorno.isoformat()),
        )
        righe = list(cur.fetchall())

        visite_anonime_per_giorno = {}
        if _table_exists(
            cur,
            "accessi_anonimi_giornalieri",
            postgres=postgres,
        ):
            cur.execute(
                """
                SELECT giorno, visite_sessione
                FROM accessi_anonimi_giornalieri
                WHERE giorno >= ?
                  AND giorno <= ?
                ORDER BY giorno ASC
                """,
                (inizio_mese.isoformat(), giorno.isoformat()),
            )
            visite_anonime_per_giorno = {
                _parse_day(_row_value(row, "giorno", 0)): int(
                    _row_value(row, "visite_sessione", 1) or 0
                )
                for row in cur.fetchall()
            }
    finally:
        try:
            cur.close()
        except Exception:
            pass

    utenti_per_giorno = defaultdict(set)
    zona_recente_per_utente = {}

    for row in righe:
        data_accesso = _parse_day(_row_value(row, "giorno", 0))
        utente_id = int(_row_value(row, "utente_id", 1))
        zona = normalizza_zona(_row_value(row, "zona", 2))
        utenti_per_giorno[data_accesso].add(utente_id)
        zona_recente_per_utente[utente_id] = zona

    utenti_oggi = set(utenti_per_giorno.get(giorno, set()))
    utenti_settimana = set()
    utenti_mese = set()

    serie = []
    picco = 0
    anonimi_settimana = 0
    anonimi_mese = 0
    for indice in range(ACCESS_WINDOW_DAYS):
        data_grafico = inizio_mese + timedelta(days=indice)
        utenti = utenti_per_giorno.get(data_grafico, set())
        valore = len(utenti)
        anonimi = int(visite_anonime_per_giorno.get(data_grafico, 0))
        totale = valore + anonimi
        picco = max(picco, totale)
        utenti_mese.update(utenti)
        anonimi_mese += anonimi
        if data_grafico >= inizio_settimana:
            utenti_settimana.update(utenti)
            anonimi_settimana += anonimi
        serie.append({
            "data": data_grafico.isoformat(),
            "etichetta": data_grafico.strftime("%d/%m"),
            "valore": valore,
            "registrati": valore,
            "anonimi": anonimi,
            "totale": totale,
        })

    zone_counter = Counter(
        zona_recente_per_utente[utente_id]
        for utente_id in utenti_mese
        if utente_id in zona_recente_per_utente
    )
    totale_zone = sum(zone_counter.values())
    zone = []
    for nome, totale in zone_counter.most_common(8):
        zone.append({
            "nome": nome,
            "totale": totale,
            "percentuale": round(
                (totale / totale_zone * 100) if totale_zone else 0,
                1,
            ),
        })

    altre = sum(zone_counter.values()) - sum(item["totale"] for item in zone)
    if altre:
        zone.append({
            "nome": "Altre zone",
            "totale": altre,
            "percentuale": round(altre / totale_zone * 100, 1),
        })

    return {
        "oggi": len(utenti_oggi),
        "settimana": len(utenti_settimana),
        "mese": len(utenti_mese),
        "anonimi_oggi": int(visite_anonime_per_giorno.get(giorno, 0)),
        "anonimi_settimana": anonimi_settimana,
        "anonimi_mese": anonimi_mese,
        "serie": serie,
        "picco": picco,
        "zone": zone,
        "giorni_con_dati": sum(1 for item in serie if item["totale"]),
    }
