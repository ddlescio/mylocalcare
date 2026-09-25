"""Regole pure per la disponibilita ai servizi degli utenti.

Il modulo non dipende da Flask o dal database: riceve strutture Python,
restituisce un payload canonico e solleva ``ValueError`` per dati non validi.
Non sono previsti campi di testo libero, cosi recapiti e note personali non
possono finire accidentalmente nella disponibilita pubblica.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Mapping


STATI_DISPONIBILITA = (
    "disponibile",
    "limitata",
    "non_disponibile",
)
FASCE_DISPONIBILITA = (
    "mattina",
    "pomeriggio",
    "sera",
    "notte",
)
TIPI_DATA_SPECIALE = (
    "disponibile",
    "non_disponibile",
)
CATEGORIE_SERVIZI = (
    "operatori-benessere",
    "aiuto-in-casa",
    "ripetizioni",
    "babysitter",
    "pet-sitter",
    "caregiver",
    "escursioni-sport",
    "biglietti-spettacoli",
    "libri-scuola",
    "caffe-parole",
    "family-kids",
    "eventi-socialita",
    "spazi-sale",
)

MAX_RIGHE_SETTIMANALI = 28
MAX_DATE_SPECIALI = 180
MAX_ASSENZE = 60

GIORNI_RICONFERMA = 30
GIORNI_PRIORITA_RIDOTTA = 37
GIORNI_ESCLUSIONE_FILTRO = 44

CODICE_FRESCA = "aggiornata"
CODICE_RICONFERMA = "da_riconfermare"
CODICE_PRIORITA_RIDOTTA = "priorita_ridotta"
CODICE_ESCLUSA_FILTRO = "esclusa_filtro"
CODICE_MAI_CONFERMATA = "mai_confermata"

_TOP_LEVEL_FIELDS = frozenset({
    "stato",
    "settimanale",
    "date_speciali",
    "assenze",
})
_WEEKLY_FIELDS = frozenset({"giorno_settimana", "fascia"})
_SPECIAL_DATE_FIELDS = frozenset({"data", "tipo", "fasce"})
_ABSENCE_FIELDS = frozenset({"data_inizio", "data_fine"})
_FASCIA_ORDER = {value: index for index, value in enumerate(FASCE_DISPONIBILITA)}


def _require_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} deve essere un oggetto")
    return value


def _reject_unknown_fields(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    field_name: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(
            f"{field_name} contiene campi non consentiti: {', '.join(unknown)}"
        )


def _require_list(value: Any, field_name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name} deve essere una lista")
    return value


def _bounded_list(value: Any, field_name: str, limit: int) -> list[Any]:
    rows = _require_list(value, field_name)
    if len(rows) > limit:
        raise ValueError(f"{field_name} non puo contenere piu di {limit} elementi")
    return rows


def _enum(value: Any, allowed: tuple[str, ...], field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} non valido")
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise ValueError(f"{field_name} non valido")
    return normalized


def _iso_date(value: Any, field_name: str) -> date:
    if isinstance(value, datetime):
        raise ValueError(f"{field_name} deve usare il formato YYYY-MM-DD")
    if isinstance(value, date):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field_name} deve usare il formato YYYY-MM-DD")
    text = value.strip()
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} deve usare il formato YYYY-MM-DD"
        ) from exc
    if text != parsed.isoformat():
        raise ValueError(f"{field_name} deve usare il formato YYYY-MM-DD")
    return parsed


def _normalize_weekly(value: Any) -> list[dict[str, Any]]:
    rows = _bounded_list(value, "settimanale", MAX_RIGHE_SETTIMANALI)
    normalized: set[tuple[int, str]] = set()
    for index, raw_row in enumerate(rows):
        row_name = f"settimanale[{index}]"
        row = _require_mapping(raw_row, row_name)
        _reject_unknown_fields(row, _WEEKLY_FIELDS, row_name)
        day = row.get("giorno_settimana")
        if isinstance(day, bool) or not isinstance(day, int) or not 1 <= day <= 7:
            raise ValueError(
                f"{row_name}.giorno_settimana deve essere compreso tra 1 e 7"
            )
        slot = _enum(row.get("fascia"), FASCE_DISPONIBILITA, f"{row_name}.fascia")
        normalized.add((day, slot))

    return [
        {"giorno_settimana": day, "fascia": slot}
        for day, slot in sorted(
            normalized,
            key=lambda item: (item[0], _FASCIA_ORDER[item[1]]),
        )
    ]


def _normalize_special_dates(value: Any) -> list[dict[str, Any]]:
    rows = _bounded_list(value, "date_speciali", MAX_DATE_SPECIALI)
    by_date: dict[date, dict[str, Any]] = {}
    for index, raw_row in enumerate(rows):
        row_name = f"date_speciali[{index}]"
        row = _require_mapping(raw_row, row_name)
        _reject_unknown_fields(row, _SPECIAL_DATE_FIELDS, row_name)
        day = _iso_date(row.get("data"), f"{row_name}.data")
        special_type = _enum(
            row.get("tipo"),
            TIPI_DATA_SPECIALE,
            f"{row_name}.tipo",
        )
        raw_slots = _require_list(row.get("fasce"), f"{row_name}.fasce")
        slots = {
            _enum(slot, FASCE_DISPONIBILITA, f"{row_name}.fasce")
            for slot in raw_slots
        }

        if special_type == "non_disponibile" and slots:
            raise ValueError(
                f"{row_name}.fasce deve essere vuoto per una data non disponibile"
            )
        if special_type == "disponibile" and not slots:
            raise ValueError(
                f"{row_name}.fasce deve indicare almeno una fascia disponibile"
            )

        previous = by_date.get(day)
        if previous and previous["tipo"] != special_type:
            raise ValueError(
                f"date_speciali contiene indicazioni in conflitto per {day.isoformat()}"
            )
        if previous:
            previous["fasce"].update(slots)
        else:
            by_date[day] = {"tipo": special_type, "fasce": set(slots)}

    if len(by_date) > MAX_DATE_SPECIALI:
        raise ValueError(
            f"date_speciali non puo contenere piu di {MAX_DATE_SPECIALI} date"
        )

    return [
        {
            "data": day.isoformat(),
            "tipo": data["tipo"],
            "fasce": sorted(data["fasce"], key=_FASCIA_ORDER.__getitem__),
        }
        for day, data in sorted(by_date.items())
    ]


def _normalize_absences(value: Any) -> list[dict[str, str]]:
    rows = _bounded_list(value, "assenze", MAX_ASSENZE)
    periods: set[tuple[date, date]] = set()
    for index, raw_row in enumerate(rows):
        row_name = f"assenze[{index}]"
        row = _require_mapping(raw_row, row_name)
        _reject_unknown_fields(row, _ABSENCE_FIELDS, row_name)
        start = _iso_date(row.get("data_inizio"), f"{row_name}.data_inizio")
        end = _iso_date(row.get("data_fine"), f"{row_name}.data_fine")
        if end < start:
            raise ValueError(f"{row_name}.data_fine precede data_inizio")
        periods.add((start, end))

    # Periodi sovrapposti o consecutivi rappresentano una sola assenza. La
    # fusione rende il payload stabile e semplifica i controlli successivi.
    merged: list[list[date]] = []
    for start, end in sorted(periods):
        if merged and start <= merged[-1][1] + timedelta(days=1):
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])

    if len(merged) > MAX_ASSENZE:
        raise ValueError(f"assenze non puo contenere piu di {MAX_ASSENZE} periodi")

    return [
        {"data_inizio": start.isoformat(), "data_fine": end.isoformat()}
        for start, end in merged
    ]


def normalize_disponibilita_payload(payload: Any) -> dict[str, Any]:
    """Valida e normalizza la disponibilita di un utente.

    I duplicati esatti vengono eliminati, le fasce sono ordinate in modo
    stabile e i periodi di assenza sovrapposti o consecutivi sono uniti.
    """

    data = _require_mapping(payload, "disponibilita")
    _reject_unknown_fields(data, _TOP_LEVEL_FIELDS, "disponibilita")
    status = _enum(data.get("stato"), STATI_DISPONIBILITA, "stato")
    weekly = _normalize_weekly(data.get("settimanale"))
    special_dates = _normalize_special_dates(data.get("date_speciali"))
    absences = _normalize_absences(data.get("assenze"))

    parsed_absences = [
        (
            date.fromisoformat(period["data_inizio"]),
            date.fromisoformat(period["data_fine"]),
        )
        for period in absences
    ]
    for special in special_dates:
        if special["tipo"] != "disponibile":
            continue
        special_day = date.fromisoformat(special["data"])
        if any(start <= special_day <= end for start, end in parsed_absences):
            raise ValueError(
                "una data speciale disponibile non puo ricadere in un periodo "
                f"di assenza: {special['data']}"
            )

    return {
        "stato": status,
        "settimanale": weekly,
        "date_speciali": special_dates,
        "assenze": absences,
    }


def risolvi_disponibilita_per_categoria(
    disponibilita_generale: Any,
    disponibilita_per_categoria: Any,
    categoria: Any,
) -> Any:
    """Sceglie l'agenda specifica, con fallback trasparente a quella generale.

    ``disponibilita_per_categoria`` puo essere una mapping indicizzata per slug
    oppure una lista di mapping che espongono ``categoria_slug``. Il valore
    restituito non viene copiato: il chiamante conserva i propri metadati DB.
    """

    if not isinstance(categoria, str):
        return disponibilita_generale
    category_slug = categoria.strip().lower()
    if category_slug not in CATEGORIE_SERVIZI:
        return disponibilita_generale

    if isinstance(disponibilita_per_categoria, Mapping):
        specific = disponibilita_per_categoria.get(category_slug)
        return specific if specific is not None else disponibilita_generale

    if isinstance(disponibilita_per_categoria, (list, tuple)):
        for profile in disponibilita_per_categoria:
            if not isinstance(profile, Mapping):
                continue
            if profile.get("categoria_slug") == category_slug:
                return profile
    return disponibilita_generale


def _utc_datetime(value: Any, field_name: str) -> datetime:
    if isinstance(value, date) and not isinstance(value, datetime):
        parsed = datetime.combine(value, time.min, tzinfo=timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"{field_name} non e una data/ora valida") from exc
    else:
        raise ValueError(f"{field_name} non e una data/ora valida")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def calcola_freschezza_disponibilita(
    confermata_at: Any,
    now: Any = None,
) -> dict[str, Any]:
    """Calcola riconferma, riduzione priorita ed esclusione dal filtro.

    I confini sono inclusivi: esattamente a +30 giorni serve la riconferma,
    a +37 la priorita e ridotta e a +44 il profilo non rientra piu nel filtro
    delle persone disponibili.
    """

    current = (
        datetime.now(timezone.utc)
        if now is None
        else _utc_datetime(now, "now")
    )
    boundary_days = {
        "riconferma": GIORNI_RICONFERMA,
        "priorita_ridotta": GIORNI_PRIORITA_RIDOTTA,
        "esclusione_filtro": GIORNI_ESCLUSIONE_FILTRO,
    }

    if confermata_at is None or confermata_at == "":
        return {
            "codice": CODICE_MAI_CONFERMATA,
            "confermata_at": None,
            "giorni_trascorsi": None,
            "riconferma_richiesta": True,
            "priorita_ridotta": True,
            "inclusa_filtro_disponibili": False,
            "confini_giorni": boundary_days,
            "confini_at": {
                "riconferma": None,
                "priorita_ridotta": None,
                "esclusione_filtro": None,
            },
        }

    confirmed = _utc_datetime(confermata_at, "confermata_at")
    boundaries = {
        "riconferma": confirmed + timedelta(days=GIORNI_RICONFERMA),
        "priorita_ridotta": confirmed + timedelta(days=GIORNI_PRIORITA_RIDOTTA),
        "esclusione_filtro": confirmed + timedelta(days=GIORNI_ESCLUSIONE_FILTRO),
    }

    if current >= boundaries["esclusione_filtro"]:
        code = CODICE_ESCLUSA_FILTRO
    elif current >= boundaries["priorita_ridotta"]:
        code = CODICE_PRIORITA_RIDOTTA
    elif current >= boundaries["riconferma"]:
        code = CODICE_RICONFERMA
    else:
        code = CODICE_FRESCA

    elapsed_seconds = (current - confirmed).total_seconds()
    elapsed_days = int(elapsed_seconds // 86400)
    return {
        "codice": code,
        "confermata_at": _iso_utc(confirmed),
        "giorni_trascorsi": elapsed_days,
        "riconferma_richiesta": current >= boundaries["riconferma"],
        "priorita_ridotta": current >= boundaries["priorita_ridotta"],
        "inclusa_filtro_disponibili": current < boundaries["esclusione_filtro"],
        "confini_giorni": boundary_days,
        "confini_at": {
            key: _iso_utc(value) for key, value in boundaries.items()
        },
    }


def serializza_disponibilita_pubblica(
    disponibilita: Any,
    confermata_at: Any = None,
    now: Any = None,
) -> dict[str, Any]:
    """Restituisce soltanto i dati di disponibilita ammessi in pubblico.

    Eventuali chiavi tecniche presenti nella riga DB (utente, audit, note) non
    vengono copiate. La data/ora completa di conferma resta privata: in
    pubblico viene esposta soltanto la data e lo stato di freschezza utile.
    """

    source = _require_mapping(disponibilita, "disponibilita")
    whitelisted = {key: source.get(key) for key in _TOP_LEVEL_FIELDS}
    normalized = normalize_disponibilita_payload(whitelisted)
    freshness = calcola_freschezza_disponibilita(confermata_at, now=now)
    confirmed = freshness["confermata_at"]
    normalized["freschezza"] = {
        "codice": freshness["codice"],
        "riconferma_richiesta": freshness["riconferma_richiesta"],
        "priorita_ridotta": freshness["priorita_ridotta"],
        "inclusa_filtro_disponibili": freshness[
            "inclusa_filtro_disponibili"
        ],
        "confermata_il": confirmed[:10] if confirmed else None,
    }
    return normalized


__all__ = [
    "STATI_DISPONIBILITA",
    "FASCE_DISPONIBILITA",
    "TIPI_DATA_SPECIALE",
    "CATEGORIE_SERVIZI",
    "MAX_RIGHE_SETTIMANALI",
    "MAX_DATE_SPECIALI",
    "MAX_ASSENZE",
    "GIORNI_RICONFERMA",
    "GIORNI_PRIORITA_RIDOTTA",
    "GIORNI_ESCLUSIONE_FILTRO",
    "CODICE_FRESCA",
    "CODICE_RICONFERMA",
    "CODICE_PRIORITA_RIDOTTA",
    "CODICE_ESCLUSA_FILTRO",
    "CODICE_MAI_CONFERMATA",
    "normalize_disponibilita_payload",
    "risolvi_disponibilita_per_categoria",
    "calcola_freschezza_disponibilita",
    "serializza_disponibilita_pubblica",
]
