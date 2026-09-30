"""Regole pure per il ciclo di vita degli annunci ``offro``.

Il modulo non accede al database e non invia comunicazioni. Riceve lo stato
persistito del ciclo e la disponibilita effettiva, poi restituisce le azioni
dovute. Un acquisto riconferma la disponibilita a monte e fa ripartire questo
ciclo ordinario, senza introdurre eccezioni temporali separate. In questo
modo cron, test e interfaccia condividono gli stessi confini temporali.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable


ORIGINE_ORDINARIA = "ordinario"
ORIGINE_ROLLOUT = "rollout"

STATO_ATTIVO = "attivo"
STATO_NON_DISPONIBILE = "non_disponibile_scadenza"
STATO_ARCHIVIATO = "archiviato"
STATO_COMPLETATO = "completato"

GIORNI_ORDINARI_NON_DISPONIBILE = 37
GIORNI_ORDINARI_ARCHIVIAZIONE = 44

GIORNI_ROLLOUT_PROMEMORIA_1 = 7
GIORNI_ROLLOUT_PROMEMORIA_2 = 14
GIORNI_ROLLOUT_ULTIMO_AVVISO = 21
GIORNI_ROLLOUT_ARCHIVIAZIONE = 28

EVENTO_ROLLOUT_INVITO = "rollout_invito"
EVENTO_ROLLOUT_PROMEMORIA_1 = "rollout_promemoria_1"
EVENTO_ROLLOUT_PROMEMORIA_2 = "rollout_promemoria_2"
EVENTO_ROLLOUT_ULTIMO_AVVISO = "rollout_ultimo_avviso"
EVENTO_ARCHIVIATO = "annuncio_archiviato"

EVENTI_ROLLOUT = (
    (EVENTO_ROLLOUT_INVITO, 0),
    (EVENTO_ROLLOUT_PROMEMORIA_1, GIORNI_ROLLOUT_PROMEMORIA_1),
    (EVENTO_ROLLOUT_PROMEMORIA_2, GIORNI_ROLLOUT_PROMEMORIA_2),
    (EVENTO_ROLLOUT_ULTIMO_AVVISO, GIORNI_ROLLOUT_ULTIMO_AVVISO),
)


def utc_datetime(value: Any) -> datetime | None:
    """Converte timestamp SQLite/PostgreSQL in UTC, senza sollevare errori."""

    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, datetime.min.time())
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def pianifica_ciclo_annuncio(
    *,
    origine: str,
    iniziato_at: Any,
    confermata_at: Any = None,
    stato_disponibilita: str | None = None,
    now: Any = None,
    eventi_inviati: Iterable[str] = (),
) -> dict[str, Any]:
    """Calcola azioni, stato pubblico e archivio senza effetti collaterali."""

    current = utc_datetime(now) or datetime.now(timezone.utc)
    started = utc_datetime(iniziato_at)
    confirmed = utc_datetime(confermata_at)
    sent = {str(code) for code in eventi_inviati}

    if origine not in {ORIGINE_ORDINARIA, ORIGINE_ROLLOUT}:
        raise ValueError("Origine ciclo disponibilita non valida")
    if started is None:
        raise ValueError("Data iniziale ciclo disponibilita non valida")

    normalized_status = str(stato_disponibilita or "").strip().lower()
    voluntarily_unavailable = normalized_status == "non_disponibile"

    # Una conferma reale chiude sempre il rollout iniziale. Il chiamante puo
    # trasformare la riga in ciclo ordinario usando questo segnale.
    rollout_completed = bool(origine == ORIGINE_ROLLOUT and confirmed)

    due_events: list[str] = []
    if origine == ORIGINE_ROLLOUT and not rollout_completed:
        # Gli eventi del rollout sono progressivi. Se il job riparte in
        # ritardo inviamo soltanto la fase piu urgente maturata; una volta
        # registrata una fase non dobbiamo tornare nei giorni successivi a
        # spedire i promemoria precedenti rimasti intenzionalmente saltati.
        sent_ranks = [
            index
            for index, (code, _days) in enumerate(EVENTI_ROLLOUT)
            if code in sent
        ]
        highest_sent_rank = max(sent_ranks, default=-1)
        latest_rollout_event = None
        for index, (code, days) in enumerate(EVENTI_ROLLOUT):
            if (
                index > highest_sent_rank
                and current >= started + timedelta(days=days)
                and code not in sent
            ):
                latest_rollout_event = code
        # Se il job e rimasto fermo non sommergiamo l'utente con tutti gli
        # avvisi arretrati: inviamo soltanto la fase piu urgente maturata.
        if latest_rollout_event:
            due_events.append(latest_rollout_event)

    if rollout_completed:
        return {
            "rollout_completato": True,
            "stato": STATO_COMPLETATO,
            "non_disponibile_effettiva": False,
            "archive_due_at": None,
            "archivia_ora": False,
            "eventi_dovuti": due_events,
        }

    if voluntarily_unavailable:
        # E una scelta esplicita dell'utente: l'annuncio esce subito dal
        # ciclo, senza attendere i confini 37/44 e senza generare gli avvisi
        # previsti per una mancata riconferma.
        return {
            "rollout_completato": False,
            "stato": STATO_ARCHIVIATO,
            "non_disponibile_effettiva": True,
            "archive_due_at": None,
            "archivia_ora": True,
            "eventi_dovuti": [],
        }

    if origine == ORIGINE_ROLLOUT:
        unavailable_at = started + timedelta(
            days=GIORNI_ROLLOUT_ULTIMO_AVVISO
        )
        base_archive_at = started + timedelta(
            days=GIORNI_ROLLOUT_ARCHIVIAZIONE
        )
    else:
        if confirmed is None:
            return {
                "rollout_completato": False,
                "stato": STATO_ATTIVO,
                "non_disponibile_effettiva": False,
                "archive_due_at": None,
                "archivia_ora": False,
                "eventi_dovuti": due_events,
            }
        unavailable_at = confirmed + timedelta(
            days=GIORNI_ORDINARI_NON_DISPONIBILE
        )
        base_archive_at = confirmed + timedelta(
            days=GIORNI_ORDINARI_ARCHIVIAZIONE
        )

    effective_unavailable = current >= unavailable_at
    archive_now = bool(
        effective_unavailable
        and current >= base_archive_at
    )
    if archive_now and EVENTO_ARCHIVIATO not in sent:
        due_events.append(EVENTO_ARCHIVIATO)

    if archive_now:
        state = STATO_ARCHIVIATO
    elif effective_unavailable:
        state = STATO_NON_DISPONIBILE
    else:
        state = STATO_ATTIVO

    return {
        "rollout_completato": False,
        "stato": state,
        "non_disponibile_effettiva": effective_unavailable,
        "archive_due_at": base_archive_at,
        "archivia_ora": archive_now,
        "eventi_dovuti": list(dict.fromkeys(due_events)),
    }


__all__ = [name for name in globals() if name.isupper()] + [
    "pianifica_ciclo_annuncio",
    "utc_datetime",
]
