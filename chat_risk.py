"""Regole trasparenti per individuare un uso anomalo delle nuove chat."""


CHAT_RISK_THRESHOLDS = {
    "nuove_chat_24h": 10,
    "nuove_chat_7g": 25,
    "nuove_chat_30g": 45,
    "giorni_attivi_7g": 4,
    "chat_continuative_7g": 16,
    "regioni_contattate_7g": 4,
    "chat_multiregione_7g": 10,
    "province_contattate_7g": 6,
    "chat_multiprovincia_7g": 12,
    "senza_risposta_7g": 12,
    "blocchi_ricevuti_30g": 2,
}


def valuta_rischio_chat(metriche, soglie=None):
    """
    Valuta le metriche delle sole conversazioni iniziate dall'utente.

    Il risultato serve a portare un caso all'attenzione dell'admin. Non causa
    mai automaticamente la sospensione o la disattivazione dell'account.
    """
    soglie = {**CHAT_RISK_THRESHOLDS, **(soglie or {})}

    valori = {
        chiave: int(metriche.get(chiave) or 0)
        for chiave in CHAT_RISK_THRESHOLDS
    }
    motivi = []

    if valori["nuove_chat_24h"] >= soglie["nuove_chat_24h"]:
        motivi.append(
            f'{valori["nuove_chat_24h"]} nuove conversazioni in 24 ore'
        )

    if valori["nuove_chat_7g"] >= soglie["nuove_chat_7g"]:
        motivi.append(
            f'{valori["nuove_chat_7g"]} nuove conversazioni in 7 giorni'
        )

    if valori["nuove_chat_30g"] >= soglie["nuove_chat_30g"]:
        motivi.append(
            f'{valori["nuove_chat_30g"]} nuove conversazioni in 30 giorni'
        )

    if (
        valori["giorni_attivi_7g"] >= soglie["giorni_attivi_7g"]
        and valori["nuove_chat_7g"] >= soglie["chat_continuative_7g"]
    ):
        motivi.append(
            f'attività continuativa per {valori["giorni_attivi_7g"]} giorni su 7'
        )

    if (
        valori["regioni_contattate_7g"] >= soglie["regioni_contattate_7g"]
        and valori["nuove_chat_7g"] >= soglie["chat_multiregione_7g"]
    ):
        motivi.append(
            f'contatti distribuiti in {valori["regioni_contattate_7g"]} regioni'
        )
    elif (
        valori["province_contattate_7g"] >= soglie["province_contattate_7g"]
        and valori["nuove_chat_7g"] >= soglie["chat_multiprovincia_7g"]
    ):
        motivi.append(
            f'contatti distribuiti in {valori["province_contattate_7g"]} province'
        )

    if valori["senza_risposta_7g"] >= soglie["senza_risposta_7g"]:
        motivi.append(
            f'{valori["senza_risposta_7g"]} conversazioni senza risposta in 7 giorni'
        )

    if valori["blocchi_ricevuti_30g"] >= soglie["blocchi_ricevuti_30g"]:
        motivi.append(
            f'bloccato da {valori["blocchi_ricevuti_30g"]} utenti negli ultimi 30 giorni'
        )

    # Punteggio usato soltanto per ordinare i casi più urgenti in alto.
    punteggio = (
        valori["nuove_chat_24h"] * 5
        + valori["nuove_chat_7g"] * 2
        + valori["nuove_chat_30g"]
        + valori["giorni_attivi_7g"] * 3
        + valori["regioni_contattate_7g"] * 4
        + valori["province_contattate_7g"] * 2
        + valori["senza_risposta_7g"] * 2
        + valori["blocchi_ricevuti_30g"] * 10
    )

    return {
        "sospetto": bool(motivi),
        "motivi": motivi,
        "motivo": " · ".join(motivi),
        "punteggio": punteggio,
        **valori,
    }
