"""Dominio isolato per inviti e referenze professionali.

Il modulo non importa Flask o ``app``.  Le informazioni di contatto del
referente vengono cifrate con AES-GCM usando chiavi derivate da un segreto
master fornito esplicitamente dal chiamante.  Nel database il token di invito
e l'indirizzo normalizzato sono rappresentati soltanto da impronte hash.
"""

from __future__ import annotations

import base64
from datetime import date
import hashlib
import hmac
import re
import secrets
from typing import Any, Mapping

from Crypto.Cipher import AES


REFERENCE_RESPONSE_STATES = {
    "in_attesa",
    "risposta_ricevuta",
    "rifiutata",
    "scaduta",
    "revocata",
    "cancellata",
}

REFERENCE_VERIFICATION_STATES = {
    "non_esaminata",
    "in_coda",
    "verificata",
    "non_confermata",
    "non_verificabile",
    "revocata",
}

REFERENCE_VERIFICATION_METHODS = {
    "nessuno",
    "email",
    "telefono",
    "altro",
}

REFERENCE_RELATION_TYPES = {
    "famiglia",
    "datore_lavoro",
    "cliente",
    "struttura",
    "altro",
}

REFERENCE_DURATION_RANGES = {
    "meno_3_mesi",
    "3_6_mesi",
    "6_12_mesi",
    "1_2_anni",
    "oltre_2_anni",
}

RELATION_LABELS = {
    "famiglia": "Famiglia",
    "datore_lavoro": "Datore di lavoro",
    "cliente": "Cliente",
    "struttura": "Struttura",
    "altro": "Altro rapporto professionale",
}

DURATION_LABELS = {
    "meno_3_mesi": "Meno di 3 mesi",
    "3_6_mesi": "3–6 mesi",
    "6_12_mesi": "6–12 mesi",
    "1_2_anni": "1–2 anni",
    "oltre_2_anni": "Oltre 2 anni",
}

VERIFICATION_LABELS = {
    "non_esaminata": "Referenza ricevuta",
    "in_coda": "Controllo MyLocalCare in corso",
    "verificata": "Controllata da MyLocalCare",
    "non_confermata": "Non confermata",
    "non_verificabile": "Non verificabile",
    "revocata": "Revocata",
}

RESPONSE_LABELS = {
    "in_attesa": "In attesa del referente",
    "risposta_ricevuta": "Referenza ricevuta",
    "rifiutata": "Invito rifiutato",
    "scaduta": "Invito scaduto",
    "revocata": "Referenza revocata",
    "cancellata": "Referenza cancellata",
}

VERIFICATION_METHOD_LABELS = {
    "nessuno": "Nessun controllo",
    "email": "Contatto email",
    "telefono": "Contatto telefonico",
    "altro": "Altro riscontro",
}

REFERENCE_CONSENT_VERSION = "references_2026_v2"
REFERENCE_KEY_ID = "references-pii-v1"
REFERENCE_TOKEN_BYTES = 32

_CATEGORY_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_EMAIL_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"^[0-9+().\s/\-]+$")
_PUBLIC_CONTACT_PATTERNS = (
    re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE),
    re.compile(r"(?:\+?\d[\s().-]*){8,}"),
    re.compile(r"\b(?:https?://|www\.|wa\.me/|t\.me/)\S+", re.IGNORECASE),
    # Intercetta anche domini e profili social scritti senza http/www: sono
    # comunque recapiti diretti e non devono finire nel testo pubblico.
    re.compile(
        r"\b(?:[a-z0-9-]+\.)+(?:it|com|org|net|eu|io)(?:/[^\s]*)?",
        re.IGNORECASE,
    ),
    re.compile(r"(?<!\w)@[a-z0-9._-]{3,}\b", re.IGNORECASE),
)


def _master_secret_bytes(master_secret: str | bytes) -> bytes:
    """Normalizza il segreto master senza leggerlo dall'ambiente."""

    if isinstance(master_secret, bytes):
        secret = master_secret
    elif isinstance(master_secret, str):
        raw = master_secret.strip()
        if not raw:
            raise ValueError("Segreto master mancante.")
        if len(raw) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            secret = bytes.fromhex(raw)
        else:
            secret = raw.encode("utf-8")
    else:
        raise TypeError("Il segreto master deve essere testo o bytes.")

    if len(secret) < 32:
        raise ValueError("Il segreto master deve contenere almeno 32 byte.")
    return secret


def _derive_key(
    master_secret: str | bytes,
    *,
    purpose: str,
    key_id: str = REFERENCE_KEY_ID,
) -> bytes:
    if not purpose or not key_id:
        raise ValueError("Purpose e key_id sono obbligatori.")
    secret = _master_secret_bytes(master_secret)
    context = f"mylocalcare:referenze:{key_id}:{purpose}".encode("utf-8")
    return hmac.new(secret, context, hashlib.sha256).digest()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("Valore cifrato non valido.")
    try:
        return base64.b64decode(
            value.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Valore cifrato non valido.") from exc


def _encrypt_private_text(
    value: str,
    master_secret: str | bytes,
    *,
    field: str,
    key_id: str = REFERENCE_KEY_ID,
) -> dict[str, str]:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} mancante.")
    key = _derive_key(master_secret, purpose=f"encrypt:{field}", key_id=key_id)
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(f"mylocalcare:referenze:{key_id}:{field}".encode("utf-8"))
    ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf-8"))
    return {
        "cifrato": _b64encode(ciphertext),
        "nonce": _b64encode(nonce),
        "tag": _b64encode(tag),
        "key_id": key_id,
    }


def _decrypt_private_text(
    ciphertext: str,
    nonce: str,
    tag: str,
    master_secret: str | bytes,
    *,
    field: str,
    key_id: str = REFERENCE_KEY_ID,
) -> str:
    key = _derive_key(master_secret, purpose=f"encrypt:{field}", key_id=key_id)
    cipher = AES.new(key, AES.MODE_GCM, nonce=_b64decode(nonce))
    cipher.update(f"mylocalcare:referenze:{key_id}:{field}".encode("utf-8"))
    try:
        plaintext = cipher.decrypt_and_verify(
            _b64decode(ciphertext),
            _b64decode(tag),
        )
    except (ValueError, KeyError) as exc:
        raise ValueError("Dato privato non autenticato o chiave errata.") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Dato privato non valido.") from exc


def normalize_reference_email(email: str) -> str:
    normalized = str(email or "").strip().casefold()
    if len(normalized) > 254 or not _EMAIL_RE.fullmatch(normalized):
        raise ValueError("Indirizzo email del referente non valido.")
    return normalized


def reference_email_fingerprint(
    email: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> str:
    normalized = normalize_reference_email(email)
    lookup_key = _derive_key(
        master_secret,
        purpose="email-lookup",
        key_id=key_id,
    )
    return hmac.new(
        lookup_key,
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def encrypt_reference_email(
    email: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> dict[str, str]:
    normalized = normalize_reference_email(email)
    encrypted = _encrypt_private_text(
        normalized,
        master_secret,
        field="email",
        key_id=key_id,
    )
    return {
        "email_cifrata": encrypted["cifrato"],
        "email_nonce": encrypted["nonce"],
        "email_tag": encrypted["tag"],
        "email_key_id": key_id,
        "email_hash": reference_email_fingerprint(
            normalized,
            master_secret,
            key_id=key_id,
        ),
    }


def decrypt_reference_email(
    email_cifrata: str,
    email_nonce: str,
    email_tag: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> str:
    return _decrypt_private_text(
        email_cifrata,
        email_nonce,
        email_tag,
        master_secret,
        field="email",
        key_id=key_id,
    )


def encrypt_reference_name(
    name: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> dict[str, str]:
    normalized = " ".join(str(name or "").strip().split())
    if not normalized or len(normalized) > 120:
        raise ValueError("Nome del referente non valido.")
    encrypted = _encrypt_private_text(
        normalized,
        master_secret,
        field="name",
        key_id=key_id,
    )
    return {
        "nome_cifrato": encrypted["cifrato"],
        "nome_nonce": encrypted["nonce"],
        "nome_tag": encrypted["tag"],
    }


def decrypt_reference_name(
    nome_cifrato: str,
    nome_nonce: str,
    nome_tag: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> str:
    return _decrypt_private_text(
        nome_cifrato,
        nome_nonce,
        nome_tag,
        master_secret,
        field="name",
        key_id=key_id,
    )


def normalize_reference_phone(phone: str | None) -> str | None:
    """Normalizza un recapito telefonico facoltativo senza renderlo cercabile.

    Conserviamo una formattazione leggibile per l'admin, ma imponiamo i limiti
    internazionali usuali (massimo 15 cifre) e un insieme ristretto di
    separatori. Il numero non viene mai trasformato in hash: non serve alcuna
    ricerca per telefono e così riduciamo i dati correlabili nel database.
    """

    normalized = " ".join(str(phone or "").strip().split())
    if not normalized:
        return None
    if len(normalized) > 40 or not _PHONE_RE.fullmatch(normalized):
        raise ValueError("Numero di telefono del referente non valido.")
    if normalized.count("+") > 1 or ("+" in normalized and not normalized.startswith("+")):
        raise ValueError("Numero di telefono del referente non valido.")
    digit_count = sum(character.isdigit() for character in normalized)
    if digit_count < 7 or digit_count > 15:
        raise ValueError("Numero di telefono del referente non valido.")
    return normalized


def encrypt_reference_phone(
    phone: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> dict[str, str]:
    normalized = normalize_reference_phone(phone)
    if not normalized:
        raise ValueError("Numero di telefono del referente mancante.")
    encrypted = _encrypt_private_text(
        normalized,
        master_secret,
        field="phone",
        key_id=key_id,
    )
    return {
        "telefono_cifrato": encrypted["cifrato"],
        "telefono_nonce": encrypted["nonce"],
        "telefono_tag": encrypted["tag"],
    }


def decrypt_reference_phone(
    telefono_cifrato: str,
    telefono_nonce: str,
    telefono_tag: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> str:
    return _decrypt_private_text(
        telefono_cifrato,
        telefono_nonce,
        telefono_tag,
        master_secret,
        field="phone",
        key_id=key_id,
    )


def encrypt_invitation_message(
    message: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> dict[str, str] | None:
    normalized = " ".join(str(message or "").strip().split())
    if not normalized:
        return None
    if len(normalized) > 500:
        raise ValueError("Il messaggio di invito è troppo lungo.")
    encrypted = _encrypt_private_text(
        normalized,
        master_secret,
        field="invitation-message",
        key_id=key_id,
    )
    return {
        "messaggio_invito_cifrato": encrypted["cifrato"],
        "messaggio_invito_nonce": encrypted["nonce"],
        "messaggio_invito_tag": encrypted["tag"],
    }


def decrypt_invitation_message(
    ciphertext: str,
    nonce: str,
    tag: str,
    master_secret: str | bytes,
    *,
    key_id: str = REFERENCE_KEY_ID,
) -> str:
    return _decrypt_private_text(
        ciphertext,
        nonce,
        tag,
        master_secret,
        field="invitation-message",
        key_id=key_id,
    )


def generate_reference_token() -> str:
    return secrets.token_urlsafe(REFERENCE_TOKEN_BYTES)


def hash_reference_token(token: str) -> str:
    raw = str(token or "").strip()
    if not raw:
        raise ValueError("Token mancante.")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def reference_token_matches(token: str, expected_hash: str) -> bool:
    try:
        actual = hash_reference_token(token)
    except ValueError:
        return False
    return hmac.compare_digest(actual, str(expected_hash or ""))


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().casefold() in {
        "1", "true", "on", "yes", "si", "sì",
    }


def contains_direct_contact(value: str) -> bool:
    text = str(value or "")
    return any(pattern.search(text) for pattern in _PUBLIC_CONTACT_PATTERNS)


def normalize_reference_payload(
    payload: Mapping[str, Any],
    *,
    current_year: int | None = None,
) -> dict[str, Any]:
    """Valida i dati strutturati e il testo facoltativo del referente."""

    current_year = int(current_year or date.today().year)
    category = str(payload.get("categoria_slug") or "").strip().casefold()
    if len(category) > 80 or not _CATEGORY_RE.fullmatch(category):
        raise ValueError("Ambito del servizio non valido.")

    relation = str(payload.get("tipo_rapporto") or "").strip().casefold()
    if relation not in REFERENCE_RELATION_TYPES:
        raise ValueError("Tipo di rapporto non valido.")

    duration = str(payload.get("durata_fascia") or "").strip().casefold()
    if duration not in REFERENCE_DURATION_RANGES:
        raise ValueError("Durata del rapporto non valida.")

    def parse_year(name: str) -> int | None:
        raw = payload.get(name)
        if raw is None or str(raw).strip() == "":
            return None
        try:
            year = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("Periodo della collaborazione non valido.") from exc
        if year < 1900 or year > current_year + 1:
            raise ValueError("Periodo della collaborazione non valido.")
        return year

    start_year = parse_year("anno_inizio")
    end_year = parse_year("anno_fine")
    if start_year is not None and end_year is not None and end_year < start_year:
        raise ValueError("L'anno finale non può precedere quello iniziale.")

    statement = str(payload.get("testo_referente") or "").strip()
    if len(statement) > 1500:
        raise ValueError("Il testo della referenza è troppo lungo.")
    # I nomi propri sono parte naturale di una referenza e sono ammessi.
    # Blocchiamo soltanto recapiti diretti (email, telefono e link), che
    # potrebbero esporre il referente o terzi nel profilo pubblico.
    if statement and contains_direct_contact(statement):
        raise ValueError("Il testo della referenza non può contenere recapiti.")

    publish = _as_bool(payload.get("autorizza_pubblicazione"))
    publish_statement = _as_bool(payload.get("autorizza_testo_pubblico"))
    if publish_statement and (not publish or not statement):
        raise ValueError(
            "La pubblicazione del testo richiede una referenza pubblicabile."
        )

    direct_experience = _as_bool(payload.get("esperienza_diretta"))
    contact_allowed = _as_bool(
        payload.get("autorizza_contatto_verifica")
        if "autorizza_contatto_verifica" in payload
        else payload.get("consenso_contatto")
    )
    raw_referee_phone = " ".join(
        str(payload.get("referente_telefono") or "").strip().split()
    )
    # Se il referente non conferma l'esperienza, nessun recapito deve essere
    # conservato anche quando un client obsoleto invia ancora questi campi.
    if not direct_experience:
        contact_allowed = False
        referee_phone = None
    else:
        has_phone = bool(raw_referee_phone)
        if contact_allowed != has_phone:
            raise ValueError(
                "Consenso al ricontatto telefonico e numero di telefono "
                "devono essere indicati insieme."
            )
        referee_phone = (
            normalize_reference_phone(raw_referee_phone)
            if contact_allowed
            else None
        )

    return {
        "categoria_slug": category,
        "tipo_rapporto": relation,
        "anno_inizio": start_year,
        "anno_fine": end_year,
        "durata_fascia": duration,
        "esperienza_diretta": direct_experience,
        "testo_referente": statement or None,
        "autorizza_contatto_verifica": contact_allowed,
        "referente_telefono": referee_phone,
        "autorizza_pubblicazione": publish,
        "autorizza_testo_pubblico": publish_statement,
    }


def _mapping(value: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "keys"):
        return {key: value[key] for key in value.keys()}
    raise TypeError("La referenza deve essere una mappatura.")


def reference_is_public(reference: Mapping[str, Any] | Any) -> bool:
    row = _mapping(reference)
    return (
        row.get("stato_risposta") == "risposta_ricevuta"
        and _as_bool(row.get("autorizza_pubblicazione"))
        and _as_bool(row.get("pubblicazione_approvata_admin"))
        and _as_bool(row.get("visibile_profilo"))
        and row.get("stato_verifica") not in {"revocata", "non_confermata"}
        and not row.get("revocata_at")
        and not row.get("cancellata_at")
    )


def _period_label(start_year: Any, end_year: Any) -> str | None:
    if start_year and end_year:
        if int(start_year) == int(end_year):
            return str(start_year)
        return f"{start_year}–{end_year}"
    if start_year:
        return f"Dal {start_year}"
    if end_year:
        return f"Fino al {end_year}"
    return None


def serialize_public_reference(
    reference: Mapping[str, Any] | Any,
) -> dict[str, Any] | None:
    """Crea l'allowlist pubblica, senza dati di contatto o note interne."""

    row = _mapping(reference)
    if not reference_is_public(row):
        return None

    verification = str(row.get("stato_verifica") or "non_esaminata")
    # Il processo interno di coda non è un esito pubblico: finché il controllo
    # non è concluso la scheda resta semplicemente una "Referenza ricevuta".
    public_verification = (
        "verificata" if verification == "verificata" else "non_esaminata"
    )
    result = {
        "id": row.get("id"),
        "categoria_slug": row.get("categoria_slug"),
        "tipo_rapporto": row.get("tipo_rapporto"),
        "tipo_rapporto_label": RELATION_LABELS.get(
            row.get("tipo_rapporto"),
            "Rapporto professionale",
        ),
        "periodo": _period_label(row.get("anno_inizio"), row.get("anno_fine")),
        "durata_fascia": row.get("durata_fascia"),
        "durata_label": DURATION_LABELS.get(row.get("durata_fascia")),
        "esperienza_diretta": _as_bool(row.get("esperienza_diretta")),
        "risposta_at": row.get("risposta_at"),
        "stato_verifica": public_verification,
        "stato_verifica_label": VERIFICATION_LABELS.get(
            public_verification,
            "Referenza ricevuta",
        ),
        "verificata_da_mylocalcare": verification == "verificata",
        "verificata_at": (
            row.get("verificata_at") if verification == "verificata" else None
        ),
        "nota_pubblica": (
            row.get("nota_pubblica") if verification == "verificata" else None
        ),
        "testo_referente": None,
    }
    if _as_bool(row.get("autorizza_testo_pubblico")):
        result["testo_referente"] = row.get("testo_referente")
    return result
