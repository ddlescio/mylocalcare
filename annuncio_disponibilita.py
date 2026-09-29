"""Disponibilita opzionale raccolta durante la creazione di un annuncio.

Gli annunci ``offro`` riutilizzano il profilo disponibilita per categoria.
Negli annunci ``cerco`` il medesimo selettore descrive invece quando il
servizio serve e viene conservato sull'annuncio come JSON canonico.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

from disponibilita_servizi import normalize_disponibilita_payload
from richieste_disponibilita import normalize_richiesta_disponibilita_payload


_HHMM_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")


def _form_values(form: Any, field_name: str) -> list[Any]:
    """Legge un campo multiplo sia da MultiDict sia da un mapping semplice."""

    getlist = getattr(form, "getlist", None)
    if callable(getlist):
        return list(getlist(field_name))
    value = form.get(field_name) if hasattr(form, "get") else None
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _form_value(form: Any, field_name: str, default: Any = "") -> Any:
    value = form.get(field_name, default) if hasattr(form, "get") else default
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return value


def listing_availability_from_form(form: Any) -> dict[str, Any] | None:
    """Legge il picker anche quando JavaScript non ha compilato il JSON.

    Il JSON canonico resta prioritario. Se e vuoto, i controlli HTML visibili
    vengono ricostruiti e passati allo stesso validatore severo usato dal
    flusso JavaScript, evitando perdite silenziose di giorni, fasce o orari.
    """

    raw_json = _form_value(form, "disponibilita_annuncio_json", "")
    normalized_json = normalize_listing_availability(raw_json)
    if normalized_json is not None:
        return normalized_json

    raw_days = _form_values(form, "disponibilita_annuncio_giorni")
    raw_slots = _form_values(form, "disponibilita_annuncio_fasce")
    start = str(_form_value(form, "disponibilita_annuncio_dalle", "") or "").strip()
    end = str(_form_value(form, "disponibilita_annuncio_alle", "") or "").strip()
    raw_on_call = _form_value(
        form,
        "disponibilita_annuncio_a_chiamata",
        "",
    )
    normalized_on_call = str(raw_on_call or "").strip().casefold()
    if normalized_on_call and normalized_on_call not in {
        "1", "true", "on", "yes", "si", "sì",
    }:
        raise ValueError("La disponibilita a chiamata non e valida.")
    on_call = bool(normalized_on_call)

    if not raw_days and (raw_slots or start or end):
        raise ValueError(
            "Seleziona almeno un giorno per le fasce o gli orari indicati."
        )
    if not raw_days and not raw_slots and not start and not end and not on_call:
        return None

    try:
        days = [int(value) for value in raw_days]
    except (TypeError, ValueError) as exc:
        raise ValueError("I giorni della disponibilita non sono validi.") from exc

    intervals: list[dict[str, Any]] = []
    if start or end:
        crosses_midnight = False
        if _HHMM_RE.fullmatch(start) and _HHMM_RE.fullmatch(end):
            crosses_midnight = end < start
        intervals.append({
            "ora_inizio": start,
            "ora_fine": end,
            "giorno_successivo": crosses_midnight,
        })

    payload = {
        "a_chiamata": on_call,
        "giorni": [
            {
                "giorno_settimana": day,
                "fasce": list(raw_slots),
                "intervalli": [dict(interval) for interval in intervals],
            }
            for day in days
        ],
    }
    return normalize_richiesta_disponibilita_payload(payload)


def normalize_listing_availability(raw_value: Any) -> dict[str, Any] | None:
    """Restituisce il calendario canonico oppure ``None`` se omesso."""

    if raw_value is None:
        return None
    if isinstance(raw_value, str):
        raw_value = raw_value.strip()
        if not raw_value:
            return None
        try:
            raw_value = json.loads(raw_value)
        except (TypeError, ValueError) as exc:
            raise ValueError("La disponibilita inserita non e valida.") from exc
    if not isinstance(raw_value, Mapping):
        raise ValueError("La disponibilita inserita non e valida.")
    return normalize_richiesta_disponibilita_payload(raw_value)


def request_to_service_availability(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Converte il selettore compatto nel formato del profilo ``offro``."""

    normalized = normalize_richiesta_disponibilita_payload(payload)
    weekly: list[dict[str, Any]] = []
    intervals: list[dict[str, Any]] = []
    for day in normalized["giorni"]:
        day_number = int(day["giorno_settimana"])
        weekly.extend(
            {
                "giorno_settimana": day_number,
                "fascia": slot,
            }
            for slot in day["fasce"]
        )
        intervals.extend(
            {
                "giorno_settimana": day_number,
                "ora_inizio": interval["ora_inizio"],
                "ora_fine": interval["ora_fine"],
                "giorno_successivo": bool(interval["giorno_successivo"]),
            }
            for interval in day["intervalli"]
        )

    return {
        "stato": "disponibile",
        "a_chiamata": bool(normalized["a_chiamata"]),
        "settimanale": weekly,
        "settimanale_intervalli": intervals,
        "date_speciali": [],
        "assenze": [],
    }


def service_to_request_availability(
    payload: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Adatta una disponibilita di servizio al selettore dell'annuncio.

    Il selettore compatto modifica soltanto settimana, intervalli e modalita
    ``a chiamata``. Date speciali e assenze restano nel profilo disponibilita
    e vengono conservate dal salvataggio backend.
    """

    if not payload:
        return None

    # I loader DB aggiungono metadati privati (versione, categoria, date di
    # conferma). Il normalizzatore puro accetta invece soltanto i campi della
    # disponibilita, quindi li estraiamo esplicitamente.
    normalized = normalize_disponibilita_payload({
        "stato": payload.get("stato"),
        "a_chiamata": payload.get("a_chiamata", False),
        "settimanale": payload.get("settimanale", []),
        "settimanale_intervalli": payload.get(
            "settimanale_intervalli",
            [],
        ),
        "date_speciali": payload.get("date_speciali", []),
        "assenze": payload.get("assenze", []),
    })
    days: dict[int, dict[str, Any]] = {}

    def ensure_day(day_number: int) -> dict[str, Any]:
        return days.setdefault(day_number, {
            "giorno_settimana": day_number,
            "fasce": [],
            "intervalli": [],
        })

    for row in normalized["settimanale"]:
        day = ensure_day(int(row["giorno_settimana"]))
        day["fasce"].append(row["fascia"])

    for row in normalized["settimanale_intervalli"]:
        day = ensure_day(int(row["giorno_settimana"]))
        day["intervalli"].append({
            "ora_inizio": row["ora_inizio"],
            "ora_fine": row["ora_fine"],
            "giorno_successivo": bool(row["giorno_successivo"]),
        })

    converted = {
        "a_chiamata": bool(normalized["a_chiamata"]),
        "giorni": [days[number] for number in sorted(days)],
    }
    if not converted["a_chiamata"] and not converted["giorni"]:
        return None
    return normalize_richiesta_disponibilita_payload(converted)


def serialize_sought_availability(payload: Mapping[str, Any]) -> str:
    normalized = normalize_richiesta_disponibilita_payload(payload)
    return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))


def deserialize_sought_availability(raw_value: Any) -> dict[str, Any] | None:
    """Legge in sicurezza dati persistiti; valori legacy corrotti non bloccano."""

    try:
        return normalize_listing_availability(raw_value)
    except (TypeError, ValueError):
        return None


def sought_availability_for_display(
    raw_value: Any,
) -> dict[str, Any] | None:
    """Adatta il calendario cercato ai componenti di visualizzazione."""

    normalized = deserialize_sought_availability(raw_value)
    if not normalized:
        return None
    display = request_to_service_availability(normalized)
    display.update({
        "configurata": True,
        "tipo_disponibilita": "cercata",
    })
    return display


__all__ = [
    "deserialize_sought_availability",
    "listing_availability_from_form",
    "normalize_listing_availability",
    "request_to_service_availability",
    "service_to_request_availability",
    "serialize_sought_availability",
    "sought_availability_for_display",
]
