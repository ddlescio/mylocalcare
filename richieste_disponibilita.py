"""Regole pure per le richieste di disponibilita tra utenti.

Il modulo non dipende da Flask o dal database. Normalizza soltanto dati
strutturati: nessun testo libero o recapito puo essere inserito nella richiesta.
Le verifiche sull'annuncio, sul proprietario e sugli account restano a carico
del futuro endpoint applicativo.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


STATI_RICHIESTA_DISPONIBILITA = (
    "in_attesa",
    "disponibile",
    "non_disponibile",
    "informazioni",
    "scaduta",
)

FASCE_RICHIESTA_DISPONIBILITA = (
    "mattina",
    "pomeriggio",
    "sera",
    "notte",
)

MAX_GIORNI_PER_RICHIESTA = 7
MAX_FASCE_PER_GIORNO = len(FASCE_RICHIESTA_DISPONIBILITA)
MAX_INTERVALLI_PER_GIORNO = 8
MAX_INTERVALLI_PER_RICHIESTA = 28

# Limiti che il futuro endpoint dovra applicare prima dell'inserimento.
MAX_RICHIESTE_24_ORE = 10
MAX_RICHIESTE_7_GIORNI = 30
MAX_RICHIESTE_PENDENTI = 10
MINUTI_ATTESA_STESSO_ANNUNCIO = 60
GIORNI_SCADENZA_RICHIESTA = 7

_TOP_LEVEL_FIELDS = frozenset({"a_chiamata", "giorni"})
_DAY_FIELDS = frozenset({"giorno_settimana", "fasce", "intervalli"})
_INTERVAL_FIELDS = frozenset({
    "ora_inizio",
    "ora_fine",
    "giorno_successivo",
})
_FASCIA_ORDER = {
    value: index for index, value in enumerate(FASCE_RICHIESTA_DISPONIBILITA)
}
_HHMM_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
_MINUTES_PER_DAY = 24 * 60
_MINUTES_PER_WEEK = 7 * _MINUTES_PER_DAY
_NIGHT_START_MINUTES = 18 * 60
_NIGHT_END_MINUTES = 8 * 60


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
    if not isinstance(value, list):
        raise ValueError(f"{field_name} deve essere una lista")
    return value


def _bounded_list(
    value: Any,
    field_name: str,
    limit: int,
) -> list[Any]:
    rows = _require_list(value, field_name)
    if len(rows) > limit:
        raise ValueError(
            f"{field_name} non puo contenere piu di {limit} elementi"
        )
    return rows


def _strict_integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} deve essere un numero intero")
    return value


def _non_negative_integer(value: Any, field_name: str) -> int:
    number = _strict_integer(value, field_name)
    if number < 0:
        raise ValueError(f"{field_name} non puo essere negativo")
    return number


def _enum(value: Any, allowed: tuple[str, ...], field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} non valido")
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise ValueError(f"{field_name} non valido")
    return normalized


def _parse_hhmm(value: Any, field_name: str) -> tuple[str, int]:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} deve usare il formato HH:MM")
    normalized = value.strip()
    if not _HHMM_RE.fullmatch(normalized):
        raise ValueError(f"{field_name} deve usare il formato HH:MM")
    hours, minutes = (int(part) for part in normalized.split(":"))
    return normalized, hours * 60 + minutes


def normalizza_stato_richiesta_disponibilita(value: Any) -> str:
    """Valida uno stato persistibile della richiesta."""

    return _enum(
        value,
        STATI_RICHIESTA_DISPONIBILITA,
        "stato",
    )


def _normalize_interval(
    value: Any,
    field_name: str,
) -> tuple[dict[str, Any], int, int]:
    row = _require_mapping(value, field_name)
    _reject_unknown_fields(row, _INTERVAL_FIELDS, field_name)

    start_text, start_minutes = _parse_hhmm(
        row.get("ora_inizio"),
        f"{field_name}.ora_inizio",
    )
    end_text, end_minutes = _parse_hhmm(
        row.get("ora_fine"),
        f"{field_name}.ora_fine",
    )
    next_day = row.get("giorno_successivo", False)
    if not isinstance(next_day, bool):
        raise ValueError(
            f"{field_name}.giorno_successivo deve essere booleano"
        )

    if next_day:
        if not (
            start_minutes > end_minutes
            and start_minutes >= _NIGHT_START_MINUTES
            and end_minutes <= _NIGHT_END_MINUTES
        ):
            raise ValueError(
                f"{field_name} puo usare giorno_successivo solo per "
                "un intervallo notturno oltre mezzanotte"
            )
        absolute_end = end_minutes + _MINUTES_PER_DAY
    else:
        if end_minutes <= start_minutes:
            raise ValueError(
                f"{field_name}.ora_fine deve essere successiva a ora_inizio"
            )
        absolute_end = end_minutes

    return (
        {
            "ora_inizio": start_text,
            "ora_fine": end_text,
            "giorno_successivo": next_day,
        },
        start_minutes,
        absolute_end,
    )


def _reject_overlapping_intervals(
    normalized_days: list[dict[str, Any]],
) -> None:
    """Controlla le sovrapposizioni anche tra notte e giorno seguente.

    La settimana viene trattata come circolare: per esempio domenica
    22:00-02:00 si sovrappone a lunedi 01:00-03:00.
    """

    timeline: list[tuple[int, int, int]] = []
    for day in normalized_days:
        day_offset = (day["giorno_settimana"] - 1) * _MINUTES_PER_DAY
        for interval in day["intervalli"]:
            _, start_minutes = _parse_hhmm(
                interval["ora_inizio"],
                "intervallo.ora_inizio",
            )
            _, end_minutes = _parse_hhmm(
                interval["ora_fine"],
                "intervallo.ora_fine",
            )
            if interval["giorno_successivo"]:
                end_minutes += _MINUTES_PER_DAY
            timeline.append((
                day_offset + start_minutes,
                day_offset + end_minutes,
                day["giorno_settimana"],
            ))

    if len(timeline) < 2:
        return

    timeline.sort(key=lambda item: (item[0], item[1]))
    circular = timeline + [
        (start + _MINUTES_PER_WEEK, end + _MINUTES_PER_WEEK, day)
        for start, end, day in timeline
    ]

    # Una seconda settimana serve soltanto a confrontare la coda della prima
    # con il suo inizio. Fermarsi qui evita controlli ridondanti.
    for index in range(1, len(timeline) + 1):
        previous = circular[index - 1]
        current = circular[index]
        if previous[1] > current[0]:
            raise ValueError(
                "gli intervalli precisi non possono sovrapporsi, "
                "neppure oltre mezzanotte"
            )


def normalize_richiesta_disponibilita_payload(
    payload: Any,
) -> dict[str, Any]:
    """Valida e restituisce il calendario settimanale canonico richiesto.

    Forma accettata::

        {"a_chiamata": False, "giorni": [{
            "giorno_settimana": 1,
            "fasce": ["pomeriggio"],
            "intervalli": [{
                "ora_inizio": "15:30",
                "ora_fine": "18:00",
                "giorno_successivo": False,
            }],
        }]}

    Ogni giorno deve contenere almeno una fascia ampia o un intervallo preciso.
    Fasce e intervalli possono coesistere. ``a_chiamata`` e indipendente:
    puo essere selezionato da solo oppure insieme ai giorni e agli orari.
    """

    data = _require_mapping(payload, "richiesta")
    _reject_unknown_fields(data, _TOP_LEVEL_FIELDS, "richiesta")

    a_chiamata = data.get("a_chiamata", False)
    if not isinstance(a_chiamata, bool):
        raise ValueError("richiesta.a_chiamata deve essere booleano")

    raw_days = _bounded_list(
        data.get("giorni", []),
        "richiesta.giorni",
        MAX_GIORNI_PER_RICHIESTA,
    )
    if not raw_days and not a_chiamata:
        raise ValueError(
            "seleziona almeno un giorno oppure la disponibilita a chiamata"
        )

    seen_days: set[int] = set()
    normalized_days: list[dict[str, Any]] = []
    total_intervals = 0

    for index, raw_day in enumerate(raw_days):
        field_name = f"richiesta.giorni[{index}]"
        day = _require_mapping(raw_day, field_name)
        _reject_unknown_fields(day, _DAY_FIELDS, field_name)

        day_number = _strict_integer(
            day.get("giorno_settimana"),
            f"{field_name}.giorno_settimana",
        )
        if day_number < 1 or day_number > 7:
            raise ValueError(
                f"{field_name}.giorno_settimana deve essere compreso tra 1 e 7"
            )
        if day_number in seen_days:
            raise ValueError("richiesta.giorni contiene giorni duplicati")
        seen_days.add(day_number)

        raw_slots = _bounded_list(
            day.get("fasce", []),
            f"{field_name}.fasce",
            MAX_FASCE_PER_GIORNO,
        )
        slots = sorted(
            {
                _enum(
                    slot,
                    FASCE_RICHIESTA_DISPONIBILITA,
                    f"{field_name}.fasce",
                )
                for slot in raw_slots
            },
            key=_FASCIA_ORDER.__getitem__,
        )

        raw_intervals = _bounded_list(
            day.get("intervalli", []),
            f"{field_name}.intervalli",
            MAX_INTERVALLI_PER_GIORNO,
        )
        total_intervals += len(raw_intervals)
        if total_intervals > MAX_INTERVALLI_PER_RICHIESTA:
            raise ValueError(
                "richiesta non puo contenere piu di "
                f"{MAX_INTERVALLI_PER_RICHIESTA} intervalli"
            )

        parsed_intervals = [
            _normalize_interval(
                value,
                f"{field_name}.intervalli[{interval_index}]",
            )
            for interval_index, value in enumerate(raw_intervals)
        ]
        parsed_intervals.sort(key=lambda item: (item[1], item[2]))
        intervals = [item[0] for item in parsed_intervals]

        if not slots and not intervals:
            raise ValueError(
                f"{field_name} deve contenere almeno una fascia "
                "o un intervallo preciso"
            )

        normalized_days.append({
            "giorno_settimana": day_number,
            "fasce": slots,
            "intervalli": intervals,
        })

    normalized_days.sort(key=lambda item: item["giorno_settimana"])
    _reject_overlapping_intervals(normalized_days)
    return {
        "a_chiamata": a_chiamata,
        "giorni": normalized_days,
    }


def valida_limiti_anti_abuso(
    *,
    richieste_24_ore: int,
    richieste_7_giorni: int,
    richieste_pendenti: int,
    richiesta_pendente_stesso_annuncio: bool = False,
    minuti_da_ultima_stesso_annuncio: int | None = None,
) -> dict[str, int | bool | None]:
    """Applica una policy deterministica prima di creare una richiesta.

    I conteggi arrivano dal database e includono la richiesta che si sta per
    aggiungere solo dopo il superamento di questa verifica.
    """

    counts = {
        "richieste_24_ore": _non_negative_integer(
            richieste_24_ore,
            "richieste_24_ore",
        ),
        "richieste_7_giorni": _non_negative_integer(
            richieste_7_giorni,
            "richieste_7_giorni",
        ),
        "richieste_pendenti": _non_negative_integer(
            richieste_pendenti,
            "richieste_pendenti",
        ),
    }
    if not isinstance(richiesta_pendente_stesso_annuncio, bool):
        raise ValueError(
            "richiesta_pendente_stesso_annuncio deve essere booleano"
        )
    if minuti_da_ultima_stesso_annuncio is not None:
        minuti_da_ultima_stesso_annuncio = _non_negative_integer(
            minuti_da_ultima_stesso_annuncio,
            "minuti_da_ultima_stesso_annuncio",
        )

    if richiesta_pendente_stesso_annuncio:
        raise ValueError(
            "esiste gia una richiesta in attesa per questo annuncio"
        )
    if (
        minuti_da_ultima_stesso_annuncio is not None
        and minuti_da_ultima_stesso_annuncio
        < MINUTI_ATTESA_STESSO_ANNUNCIO
    ):
        raise ValueError(
            "attendi prima di inviare una nuova richiesta per questo annuncio"
        )
    if counts["richieste_24_ore"] >= MAX_RICHIESTE_24_ORE:
        raise ValueError("limite di richieste nelle ultime 24 ore raggiunto")
    if counts["richieste_7_giorni"] >= MAX_RICHIESTE_7_GIORNI:
        raise ValueError("limite di richieste negli ultimi 7 giorni raggiunto")
    if counts["richieste_pendenti"] >= MAX_RICHIESTE_PENDENTI:
        raise ValueError("limite di richieste in attesa raggiunto")

    return {
        **counts,
        "richiesta_pendente_stesso_annuncio": (
            richiesta_pendente_stesso_annuncio
        ),
        "minuti_da_ultima_stesso_annuncio": (
            minuti_da_ultima_stesso_annuncio
        ),
    }


__all__ = [
    "STATI_RICHIESTA_DISPONIBILITA",
    "FASCE_RICHIESTA_DISPONIBILITA",
    "MAX_GIORNI_PER_RICHIESTA",
    "MAX_FASCE_PER_GIORNO",
    "MAX_INTERVALLI_PER_GIORNO",
    "MAX_INTERVALLI_PER_RICHIESTA",
    "MAX_RICHIESTE_24_ORE",
    "MAX_RICHIESTE_7_GIORNI",
    "MAX_RICHIESTE_PENDENTI",
    "MINUTI_ATTESA_STESSO_ANNUNCIO",
    "GIORNI_SCADENZA_RICHIESTA",
    "normalizza_stato_richiesta_disponibilita",
    "normalize_richiesta_disponibilita_payload",
    "valida_limiti_anti_abuso",
]
