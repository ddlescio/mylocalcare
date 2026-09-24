"""Regole e catalogo per le schede strutturate del profilo.

Le schede affiancano i campi testuali storici senza modificarli.  Questo
modulo non dipende da Flask, così validazione e presentazione degli stati
possono essere testate separatamente dall'applicazione.
"""

from __future__ import annotations

from datetime import date
import re


LEGACY_SLOT_TYPES = {
    "esperienza_1": "esperienza",
    "esperienza_2": "esperienza",
    "esperienza_3": "esperienza",
    "studio_1": "formazione",
    "studio_2": "formazione",
    "studio_3": "formazione",
    "certificazioni": "certificazione",
}

SINGLE_CARD_SLOTS = {
    key for key in LEGACY_SLOT_TYPES if key != "certificazioni"
}

PROFILE_CARD_TYPES = {"esperienza", "formazione", "certificazione"}

PROFILE_CARD_CATEGORIES = {
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
}

_DIRECT_CONTACT_PATTERNS = (
    re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE),
    re.compile(r"(?:\+?\d[\s().-]*){8,}"),
    re.compile(r"\b(?:https?://|www\.|wa\.me/|t\.me/)\S+", re.IGNORECASE),
    re.compile(
        r"\b(?:[a-z0-9-]+\.)+(?:it|com|net|org|eu|info|me|io)"
        r"(?:/[^\s]*)?\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?<!\w)@[a-z0-9._-]{3,}\b", re.IGNORECASE),
    re.compile(
        r"\b(?:instagram|facebook|linkedin|tiktok|telegram|"
        r"snapchat|youtube|ig|fb)\b\s*[:@-]?\s*[a-z0-9._-]{2,}",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:whatsapp|telegram|cellulare|telefono|chiamami|"
        r"scrivimi\s+al|contattami\s+al)\b",
        re.IGNORECASE,
    ),
)

VERIFICATION_STATES = {
    "dichiarata",
    "richiesta",
    "documento_visionato",
    "riscontro_effettuato",
    "non_confermata",
    "scaduta",
    "revocata",
}

ADMIN_VERIFICATION_STATES = {
    "documento_visionato",
    "riscontro_effettuato",
    "non_confermata",
    "scaduta",
    "revocata",
}

VERIFICATION_METHODS = {
    "nessuno",
    "documento",
    "fonte_pubblica",
    "ente_contattato",
    "altro",
}

PUBLIC_VERIFICATION_STATES = {
    "documento_visionato",
    "riscontro_effettuato",
}

PROFILE_CARD_NOTICE_VERSION = "profile_cards_2026_v1"

# Sono i campi la cui modifica rende non più valido un controllo precedente.
# I metadati tecnici e le note dell'admin non fanno parte del confronto.
CARD_CONTENT_FIELDS = (
    "legacy_key",
    "tipo_scheda",
    "catalogo_id",
    "titolo",
    "categoria_slug",
    "ente",
    "luogo",
    "data_inizio",
    "data_fine",
    "in_corso",
    "data_rilascio",
    "data_scadenza",
    "codice_qualifica",
    "descrizione",
)


def _entry(
    code,
    title,
    card_type,
    categories,
    *,
    nature="corso_attestato",
    issuer=False,
    expiry=False,
    regulated=False,
    order=100,
):
    return {
        "codice": code,
        "titolo": title,
        "tipo_scheda": card_type,
        "categorie": tuple(categories),
        "natura": nature,
        "richiede_ente": bool(issuer),
        "prevede_scadenza": bool(expiry),
        "professione_regolamentata": bool(regulated),
        "ordine": int(order),
    }


# Catalogo iniziale volutamente ampio, ma senza trasformare una competenza in
# una qualifica ufficiale. Le voci possono essere ampliate/disattivate da DB.
CATALOGO_SCHEDE_SEED = [
    # Esperienze / ruoli
    _entry("exp_babysitter", "Babysitter", "esperienza", ["babysitter", "family-kids"], nature="esperienza", order=10),
    _entry("exp_tata", "Tata", "esperienza", ["babysitter"], nature="esperienza", order=11),
    _entry("exp_educatore_infanzia", "Educatore per l'infanzia", "esperienza", ["babysitter", "family-kids"], nature="esperienza", order=12),
    _entry("exp_animatore_bambini", "Animatore per bambini", "esperienza", ["family-kids", "eventi-socialita"], nature="esperienza", order=13),
    _entry("exp_colf", "Collaboratore domestico / Colf", "esperienza", ["aiuto-in-casa"], nature="esperienza", order=20),
    _entry("exp_assistente_familiare", "Assistente familiare", "esperienza", ["caregiver", "aiuto-in-casa"], nature="esperienza", order=21),
    _entry("exp_badante", "Assistente a persone anziane / Badante", "esperienza", ["caregiver"], nature="esperienza", order=22),
    _entry("exp_oss", "Operatore Socio Sanitario (OSS)", "esperienza", ["caregiver"], nature="esperienza", order=23),
    _entry("exp_asa", "Ausiliario Socio Assistenziale (ASA)", "esperienza", ["caregiver"], nature="esperienza", order=24),
    _entry("exp_pet_sitter", "Pet sitter", "esperienza", ["pet-sitter"], nature="esperienza", order=30),
    _entry("exp_dog_sitter", "Dog sitter", "esperienza", ["pet-sitter"], nature="esperienza", order=31),
    _entry("exp_cat_sitter", "Cat sitter", "esperienza", ["pet-sitter"], nature="esperienza", order=32),
    _entry("exp_educatore_cinofilo", "Educatore cinofilo", "esperienza", ["pet-sitter"], nature="esperienza", order=33),
    _entry("exp_tutor", "Tutor scolastico", "esperienza", ["ripetizioni"], nature="esperienza", order=40),
    _entry("exp_insegnante", "Insegnante", "esperienza", ["ripetizioni", "caffe-parole"], nature="esperienza", order=41),
    _entry("exp_docente_lingue", "Insegnante di lingue", "esperienza", ["ripetizioni", "caffe-parole"], nature="esperienza", order=42),
    _entry("exp_personal_trainer", "Personal trainer", "esperienza", ["operatori-benessere", "escursioni-sport"], nature="esperienza", order=50),
    _entry("exp_istruttore_sportivo", "Istruttore sportivo", "esperienza", ["escursioni-sport"], nature="esperienza", order=51),
    _entry("exp_guida_escursionistica", "Guida escursionistica", "esperienza", ["escursioni-sport"], nature="esperienza", order=52),
    _entry("exp_operatore_benessere", "Operatore del benessere", "esperienza", ["operatori-benessere"], nature="esperienza", order=53),
    _entry("exp_massaggiatore", "Massaggiatore", "esperienza", ["operatori-benessere"], nature="esperienza", order=54),
    _entry("exp_insegnante_yoga", "Insegnante di yoga", "esperienza", ["operatori-benessere", "escursioni-sport"], nature="esperienza", order=55),
    _entry("exp_insegnante_pilates", "Insegnante di Pilates", "esperienza", ["operatori-benessere", "escursioni-sport"], nature="esperienza", order=56),
    _entry("exp_organizzatore_eventi", "Organizzatore di eventi", "esperienza", ["eventi-socialita", "family-kids", "spazi-sale"], nature="esperienza", order=60),
    _entry("exp_gestore_spazi", "Gestore di spazi o sale", "esperienza", ["spazi-sale"], nature="esperienza", order=61),
    _entry("exp_accoglienza_eventi", "Esperienza in accoglienza o biglietteria eventi", "esperienza", ["biglietti-spettacoli", "eventi-socialita"], nature="esperienza", order=62),
    _entry("exp_libreria_editoria", "Esperienza in libreria, biblioteca o editoria", "esperienza", ["libri-scuola"], nature="esperienza", order=63),
    _entry("exp_facilitatore_sociale", "Facilitatore di incontri o attività sociali", "esperienza", ["caffe-parole", "eventi-socialita"], nature="esperienza", order=64),

    # Formazione formale e percorsi di studio
    _entry("form_diploma_servizi_sociali", "Diploma in servizi socio-sanitari", "formazione", ["caregiver", "babysitter", "family-kids"], nature="titolo_studio", issuer=True, order=100),
    _entry("form_laurea_scienze_educazione", "Laurea in Scienze dell'educazione", "formazione", ["babysitter", "family-kids", "caregiver"], nature="titolo_studio", issuer=True, order=101),
    _entry("form_laurea_pedagogia", "Laurea in Pedagogia", "formazione", ["babysitter", "family-kids", "ripetizioni"], nature="titolo_studio", issuer=True, order=102),
    _entry("form_laurea_psicologia", "Laurea in Psicologia", "formazione", ["babysitter", "family-kids", "caregiver", "operatori-benessere"], nature="titolo_studio", issuer=True, order=103),
    _entry("form_laurea_infermieristica", "Laurea in Infermieristica", "formazione", ["caregiver"], nature="titolo_studio", issuer=True, regulated=True, order=104),
    _entry("form_laurea_fisioterapia", "Laurea in Fisioterapia", "formazione", ["operatori-benessere", "caregiver"], nature="titolo_studio", issuer=True, regulated=True, order=105),
    _entry("form_laurea_logopedia", "Laurea in Logopedia", "formazione", ["caregiver", "family-kids"], nature="titolo_studio", issuer=True, regulated=True, order=106),
    _entry("form_laurea_terapia_occupazionale", "Laurea in Terapia occupazionale", "formazione", ["caregiver"], nature="titolo_studio", issuer=True, regulated=True, order=107),
    _entry("form_laurea_scienze_motorie", "Laurea in Scienze motorie", "formazione", ["escursioni-sport", "operatori-benessere"], nature="titolo_studio", issuer=True, order=108),
    _entry("form_laurea_nutrizione", "Laurea pertinente all'ambito nutrizione", "formazione", ["operatori-benessere"], nature="titolo_studio", issuer=True, regulated=True, order=109),
    _entry("form_laurea_veterinaria", "Laurea in Medicina veterinaria", "formazione", ["pet-sitter"], nature="titolo_studio", issuer=True, regulated=True, order=110),
    _entry("form_tecnico_veterinario", "Percorso per tecnico veterinario", "formazione", ["pet-sitter"], nature="percorso_formativo", issuer=True, order=111),
    _entry("form_diploma", "Diploma di scuola secondaria", "formazione", ["ripetizioni", "babysitter", "caffe-parole"], nature="titolo_studio", issuer=True, order=112),
    _entry("form_laurea_generica", "Laurea", "formazione", ["ripetizioni", "caffe-parole", "eventi-socialita"], nature="titolo_studio", issuer=True, order=113),
    _entry("form_master", "Master universitario", "formazione", ["ripetizioni", "operatori-benessere", "caregiver", "family-kids"], nature="titolo_studio", issuer=True, order=114),
    _entry("form_dottorato", "Dottorato di ricerca", "formazione", ["ripetizioni"], nature="titolo_studio", issuer=True, order=115),
    _entry("form_qualifica_oss", "Qualifica di Operatore Socio Sanitario (OSS)", "formazione", ["caregiver"], nature="qualifica_professionale", issuer=True, order=120),
    _entry("form_qualifica_asa", "Qualifica di Ausiliario Socio Assistenziale (ASA)", "formazione", ["caregiver"], nature="qualifica_professionale", issuer=True, order=121),
    _entry("form_qualifica_osa", "Qualifica di Operatore Socio Assistenziale (OSA)", "formazione", ["caregiver"], nature="qualifica_professionale", issuer=True, order=122),
    _entry("form_assistente_familiare", "Corso per assistente familiare", "formazione", ["caregiver", "aiuto-in-casa"], nature="percorso_formativo", issuer=True, order=123),
    _entry("form_assistente_infanzia", "Corso per assistenza all'infanzia", "formazione", ["babysitter", "family-kids"], nature="percorso_formativo", issuer=True, order=124),
    _entry("form_educatore_cinofilo", "Corso per educatore cinofilo", "formazione", ["pet-sitter"], nature="percorso_formativo", issuer=True, order=125),
    _entry("form_toelettatura", "Corso di toelettatura", "formazione", ["pet-sitter"], nature="percorso_formativo", issuer=True, order=126),
    _entry("form_massaggio", "Corso di massaggio", "formazione", ["operatori-benessere"], nature="percorso_formativo", issuer=True, order=127),
    _entry("form_yoga", "Formazione per insegnante di yoga", "formazione", ["operatori-benessere", "escursioni-sport"], nature="percorso_formativo", issuer=True, order=128),
    _entry("form_pilates", "Formazione per insegnante di Pilates", "formazione", ["operatori-benessere", "escursioni-sport"], nature="percorso_formativo", issuer=True, order=129),
    _entry("form_animazione", "Corso di animazione e intrattenimento", "formazione", ["family-kids", "eventi-socialita"], nature="percorso_formativo", issuer=True, order=130),
    _entry("form_eventi", "Corso in organizzazione di eventi", "formazione", ["eventi-socialita", "family-kids", "spazi-sale"], nature="percorso_formativo", issuer=True, order=131),
    _entry("form_turismo_accoglienza", "Formazione in turismo, accoglienza o biglietteria", "formazione", ["biglietti-spettacoli", "eventi-socialita", "spazi-sale"], nature="percorso_formativo", issuer=True, order=132),
    _entry("form_biblioteconomia_editoria", "Formazione in biblioteconomia, libreria o editoria", "formazione", ["libri-scuola"], nature="percorso_formativo", issuer=True, order=133),
    _entry("form_mediazione_culturale", "Formazione in mediazione culturale o facilitazione", "formazione", ["caffe-parole", "eventi-socialita", "family-kids"], nature="percorso_formativo", issuer=True, order=134),

    # Certificazioni, abilitazioni e attestati
    _entry("cert_primo_soccorso", "Attestato di primo soccorso", "certificazione", ["babysitter", "caregiver", "escursioni-sport", "family-kids", "spazi-sale", "eventi-socialita"], issuer=True, expiry=True, order=200),
    _entry("cert_primo_soccorso_pediatrico", "Attestato di primo soccorso pediatrico", "certificazione", ["babysitter", "family-kids"], issuer=True, expiry=True, order=201),
    _entry("cert_blsd", "Attestato BLSD", "certificazione", ["babysitter", "caregiver", "escursioni-sport", "operatori-benessere", "family-kids", "spazi-sale"], issuer=True, expiry=True, order=202),
    _entry("cert_disostruzione_pediatrica", "Corso di disostruzione pediatrica", "certificazione", ["babysitter", "family-kids"], issuer=True, order=203),
    _entry("cert_haccp", "Attestato HACCP", "certificazione", ["aiuto-in-casa", "caregiver", "babysitter", "family-kids", "eventi-socialita", "spazi-sale"], issuer=True, expiry=True, order=204),
    _entry("cert_antincendio", "Attestato antincendio", "certificazione", ["family-kids", "eventi-socialita", "spazi-sale"], issuer=True, expiry=True, order=205),
    _entry("cert_sicurezza_lavoro", "Formazione sulla sicurezza sul lavoro", "certificazione", ["aiuto-in-casa", "caregiver", "family-kids", "eventi-socialita", "spazi-sale"], issuer=True, expiry=True, order=206),
    _entry("cert_pet_first_aid", "Corso di primo soccorso per animali", "certificazione", ["pet-sitter"], issuer=True, order=210),
    _entry("cert_educatore_cinofilo", "Qualifica o attestato di educatore cinofilo", "certificazione", ["pet-sitter"], issuer=True, order=211),
    _entry("cert_addestratore_cinofilo", "Qualifica o attestato di addestratore cinofilo", "certificazione", ["pet-sitter"], issuer=True, order=212),
    _entry("cert_operatore_pet_therapy", "Formazione in interventi assistiti con animali", "certificazione", ["pet-sitter", "caregiver", "family-kids"], issuer=True, order=213),
    _entry("cert_lingua_inglese", "Certificazione di lingua inglese", "certificazione", ["ripetizioni", "babysitter", "caffe-parole"], issuer=True, expiry=True, order=220),
    _entry("cert_lingua_francese", "Certificazione di lingua francese", "certificazione", ["ripetizioni", "babysitter", "caffe-parole"], issuer=True, expiry=True, order=221),
    _entry("cert_lingua_spagnola", "Certificazione di lingua spagnola", "certificazione", ["ripetizioni", "babysitter", "caffe-parole"], issuer=True, expiry=True, order=222),
    _entry("cert_lingua_tedesca", "Certificazione di lingua tedesca", "certificazione", ["ripetizioni", "babysitter", "caffe-parole"], issuer=True, expiry=True, order=223),
    _entry("cert_italiano_stranieri", "Certificazione per l'insegnamento dell'italiano a stranieri", "certificazione", ["ripetizioni", "caffe-parole"], issuer=True, order=224),
    _entry("cert_dsa_bes", "Formazione o attestato DSA/BES", "certificazione", ["ripetizioni", "babysitter", "family-kids"], issuer=True, order=225),
    _entry("cert_insegnamento", "Abilitazione all'insegnamento", "certificazione", ["ripetizioni"], nature="abilitazione", issuer=True, regulated=True, order=226),
    _entry("cert_albo_psicologi", "Iscrizione all'Albo degli Psicologi", "certificazione", ["operatori-benessere", "caregiver", "family-kids"], nature="iscrizione_albo", issuer=True, expiry=True, regulated=True, order=230),
    _entry("cert_albo_fisioterapisti", "Iscrizione all'Albo dei Fisioterapisti", "certificazione", ["operatori-benessere", "caregiver"], nature="iscrizione_albo", issuer=True, expiry=True, regulated=True, order=231),
    _entry("cert_albo_infermieri", "Iscrizione all'Ordine delle Professioni Infermieristiche", "certificazione", ["caregiver"], nature="iscrizione_albo", issuer=True, expiry=True, regulated=True, order=232),
    _entry("cert_albo_nutrizione", "Iscrizione all'albo professionale pertinente alla nutrizione", "certificazione", ["operatori-benessere"], nature="iscrizione_albo", issuer=True, expiry=True, regulated=True, order=233),
    _entry("cert_tessera_tecnica_sport", "Qualifica tecnica sportiva", "certificazione", ["escursioni-sport", "operatori-benessere"], issuer=True, expiry=True, order=240),
    _entry("cert_istruttore_federale", "Qualifica di istruttore federale", "certificazione", ["escursioni-sport"], issuer=True, expiry=True, order=241),
    _entry("cert_guida_ambientale", "Abilitazione o qualifica di guida ambientale escursionistica", "certificazione", ["escursioni-sport"], nature="abilitazione", issuer=True, expiry=True, order=242),
    _entry("cert_salvamento", "Brevetto di assistente bagnanti", "certificazione", ["escursioni-sport", "family-kids"], issuer=True, expiry=True, order=243),
    _entry("cert_yoga", "Certificazione per insegnamento yoga", "certificazione", ["operatori-benessere", "escursioni-sport"], issuer=True, order=244),
    _entry("cert_pilates", "Certificazione per insegnamento Pilates", "certificazione", ["operatori-benessere", "escursioni-sport"], issuer=True, order=245),
    _entry("cert_personal_trainer", "Certificazione di personal trainer", "certificazione", ["operatori-benessere", "escursioni-sport"], issuer=True, expiry=True, order=246),
    _entry("cert_massage", "Attestato in tecniche di massaggio", "certificazione", ["operatori-benessere"], issuer=True, order=247),
]


def clean_text(value, max_length, field_name, *, required=False):
    text = " ".join(str(value or "").strip().split())
    if required and not text:
        raise ValueError(f"{field_name} è obbligatorio")
    if len(text) > max_length:
        raise ValueError(f"{field_name} supera {max_length} caratteri")
    return text


def clean_multiline(value, max_length, field_name):
    lines = [line.strip() for line in str(value or "").splitlines()]
    text = "\n".join(line for line in lines if line)
    if len(text) > max_length:
        raise ValueError(f"{field_name} supera {max_length} caratteri")
    return text


def reject_direct_contacts(value, field_name):
    """Impedisce di pubblicare recapiti aggirando la sezione Contatti."""

    text = str(value or "")
    if any(pattern.search(text) for pattern in _DIRECT_CONTACT_PATTERNS):
        raise ValueError(
            f"{field_name} non può contenere telefono, email, WhatsApp o link"
        )
    return value


def clean_bool(value, field_name):
    """Converte i valori HTML/JSON senza trattare ``"false"`` come vero."""

    if isinstance(value, bool):
        return value
    if value in (None, "", 0, "0"):
        return False
    if value in (1, "1"):
        return True
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "on", "yes", "si", "sì"}:
            return True
        if normalized in {"false", "off", "no"}:
            return False
    raise ValueError(f"{field_name} non è valido")


def clean_iso_date(value, field_name):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError as exc:
        raise ValueError(f"{field_name} non è una data valida") from exc


def normalize_card_payload(payload, *, catalog_entry=None):
    """Valida un payload client e restituisce soli campi persistibili."""

    legacy_key = clean_text(
        payload.get("legacy_key"), 40, "Campo di origine", required=True
    )
    if legacy_key not in LEGACY_SLOT_TYPES:
        raise ValueError("Campo di origine non valido")

    card_type = LEGACY_SLOT_TYPES[legacy_key]
    requested_type = str(payload.get("tipo_scheda") or card_type).strip()
    if requested_type != card_type:
        raise ValueError("Tipo di scheda non coerente con il campo")

    category = clean_text(payload.get("categoria_slug"), 80, "Categoria")
    if category and category not in PROFILE_CARD_CATEGORIES:
        raise ValueError("Categoria non valida")

    catalog_id = payload.get("catalogo_id")
    if catalog_id in (None, "", 0, "0"):
        catalog_id = None
    else:
        try:
            catalog_id = int(catalog_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("Voce di catalogo non valida") from exc
        if catalog_id <= 0:
            raise ValueError("Voce di catalogo non valida")

    if catalog_id:
        if not catalog_entry or int(catalog_entry["id"]) != catalog_id:
            raise ValueError("Voce di catalogo non disponibile")
        if not clean_bool(
            _record_value(catalog_entry, "attivo", True),
            "Catalogo attivo",
        ):
            raise ValueError("Voce di catalogo non disponibile")
        if str(catalog_entry["tipo_scheda"]) != card_type:
            raise ValueError("Voce di catalogo non coerente con la scheda")
        catalog_categories = _record_value(catalog_entry, "categorie", ())
        if isinstance(catalog_categories, str):
            catalog_categories = {
                value.strip()
                for value in catalog_categories.split(",")
                if value.strip()
            }
        if category and catalog_categories and category not in catalog_categories:
            raise ValueError("Voce di catalogo non disponibile per la categoria")
        title = clean_text(
            catalog_entry["titolo"], 180, "Titolo", required=True
        )
    else:
        title = clean_text(payload.get("titolo"), 180, "Titolo", required=True)
    reject_direct_contacts(title, "Titolo")

    start_date = clean_iso_date(payload.get("data_inizio"), "Data di inizio")
    end_date = clean_iso_date(payload.get("data_fine"), "Data di fine")
    ongoing = clean_bool(payload.get("in_corso"), "In corso")
    issue_date = clean_iso_date(payload.get("data_rilascio"), "Data di rilascio")
    expiry_date = clean_iso_date(payload.get("data_scadenza"), "Data di scadenza")

    if start_date and end_date and end_date < start_date:
        raise ValueError("La data di fine precede quella di inizio")
    if issue_date and expiry_date and expiry_date < issue_date:
        raise ValueError("La scadenza precede il rilascio")
    if ongoing:
        end_date = None

    issuer = clean_text(payload.get("ente"), 180, "Ente")
    place = clean_text(payload.get("luogo"), 160, "Luogo")
    description = clean_multiline(
        payload.get("descrizione"), 1200, "Descrizione"
    )
    reject_direct_contacts(issuer, "Ente")
    reject_direct_contacts(place, "Luogo")
    reject_direct_contacts(description, "Descrizione")

    normalized = {
        "legacy_key": legacy_key,
        "tipo_scheda": card_type,
        "catalogo_id": catalog_id,
        "titolo": title,
        "categoria_slug": category,
        "ente": issuer,
        "luogo": place,
        "data_inizio": start_date,
        "data_fine": end_date,
        "in_corso": ongoing,
        "data_rilascio": issue_date,
        "data_scadenza": expiry_date,
        "codice_qualifica": clean_text(
            payload.get("codice_qualifica"), 120, "Codice"
        ),
        "descrizione": description,
    }

    if catalog_entry and clean_bool(
        _record_value(catalog_entry, "richiede_ente", False),
        "Ente richiesto",
    ) and not normalized["ente"]:
        raise ValueError("Ente è obbligatorio per questa voce di catalogo")

    return normalized


def _record_value(record, key, default=None):
    if record is None:
        return default
    try:
        value = record[key]
    except (KeyError, IndexError, TypeError):
        getter = getattr(record, "get", None)
        if getter is None:
            return default
        value = getter(key, default)
    return default if value is None else value


def _comparable_card_value(field, value):
    if field == "catalogo_id":
        return int(value) if value not in (None, "", 0, "0") else None
    if field == "in_corso":
        if value in (None, "", 0, "0", False, "false", "off", "no"):
            return False
        return True
    if field.startswith("data_"):
        return str(value or "")
    return str(value or "").strip()


def card_content_changed(previous, normalized_payload):
    """Indica se sono cambiati dati dichiarati mostrati nella scheda."""

    for field in CARD_CONTENT_FIELDS:
        before = _comparable_card_value(
            field, _record_value(previous, field)
        )
        after = _comparable_card_value(field, normalized_payload.get(field))
        if before != after:
            return True
    return False


def verification_reset_patch(previous, normalized_payload):
    """Restituisce i campi da azzerare dopo la modifica di una scheda.

    Anche una richiesta ancora in coda viene annullata: l'admin non deve
    controllare una versione diversa da quella per cui l'utente ha chiesto il
    controllo. Le schede mai inviate restano semplicemente ``dichiarata``.
    """

    state = str(_record_value(previous, "stato_verifica", "dichiarata"))
    if state == "dichiarata" or not card_content_changed(
        previous, normalized_payload
    ):
        return {}
    return {
        "stato_verifica": "dichiarata",
        "richiesta_verifica_at": None,
        "verificata_at": None,
        "verificata_da_admin_id": None,
        "metodo_verifica": "nessuno",
        "nota_pubblica": None,
    }


def public_verification_label(state):
    if state == "documento_visionato":
        return "Documento visionato da MyLocalCare"
    if state == "riscontro_effettuato":
        return "Riscontro effettuato da MyLocalCare"
    return "Dichiarato dall'utente"


def public_verification_state(state):
    """Non espone al pubblico esiti amministrativi interni o negativi."""

    if state in PUBLIC_VERIFICATION_STATES:
        return state
    return "dichiarata"


def effective_verification_state(card, *, today=None):
    """Restituisce lo stato effettivo senza perpetuare controlli scaduti.

    Una scheda con data di scadenza trascorsa non può continuare a mostrare
    pubblicamente un controllo positivo, anche se il relativo job di
    manutenzione non ha ancora aggiornato la riga nel database.
    """

    state = str(_record_value(card, "stato_verifica", "dichiarata"))
    if state not in PUBLIC_VERIFICATION_STATES:
        return state

    raw_expiry = str(_record_value(card, "data_scadenza", "") or "").strip()
    if not raw_expiry:
        return state

    try:
        expiry = date.fromisoformat(raw_expiry[:10])
    except ValueError:
        # I dati validati dall'app sono ISO; in presenza di un dato storico
        # anomalo non inventiamo comunque una scadenza.
        return state

    return "scaduta" if expiry < (today or date.today()) else state


def card_public_details(card):
    """Restituisce esclusivamente i dati destinati al popup pubblico."""

    raw_state = effective_verification_state(card)
    visible_state = public_verification_state(raw_state)
    return {
        "id": int(_record_value(card, "id")),
        "legacy_key": _record_value(card, "legacy_key", ""),
        "tipo_scheda": _record_value(card, "tipo_scheda", ""),
        "titolo": _record_value(card, "titolo", ""),
        "categoria_slug": _record_value(card, "categoria_slug", ""),
        "ente": _record_value(card, "ente", ""),
        "luogo": _record_value(card, "luogo", ""),
        "data_inizio": str(_record_value(card, "data_inizio", "")),
        "data_fine": str(_record_value(card, "data_fine", "")),
        "in_corso": bool(_record_value(card, "in_corso", False)),
        "data_rilascio": str(_record_value(card, "data_rilascio", "")),
        "data_scadenza": str(_record_value(card, "data_scadenza", "")),
        # Il codice resta disponibile a utente e admin, ma non è pubblico:
        # una sequenza numerica valida non è distinguibile con certezza da un
        # numero di telefono e non è necessaria per valutare il profilo.
        "codice_qualifica": "",
        "descrizione": _record_value(card, "descrizione", ""),
        "stato_verifica": visible_state,
        "etichetta_verifica": public_verification_label(raw_state),
        "verificata_at": (
            str(_record_value(card, "verificata_at", ""))
            if visible_state in PUBLIC_VERIFICATION_STATES
            else ""
        ),
    }


def group_cards_by_legacy_key(cards):
    grouped = {key: [] for key in LEGACY_SLOT_TYPES}
    for card in cards or []:
        key = _record_value(card, "legacy_key")
        if key in grouped:
            grouped[key].append(card)
    return grouped
