import argparse
import os
import re
import time
from pathlib import Path, PurePosixPath

from analizza_immagini_orfane import (
    aggiungi_thumbnail_derivate,
    dimensione_leggibile,
    leggi_riferimenti_database,
    scansiona_immagini,
)


GIORNI_MINIMI = 30
NUMERO_ATTESO = 85
SPAZIO_MINIMO_ATTESO = 100 * 1024 * 1024
SPAZIO_MASSIMO_ATTESO = 115 * 1024 * 1024
CONFERMA_RICHIESTA = "ELIMINA_85_ORFANE_SICURE"

parser = argparse.ArgumentParser(
    description=(
        "Elimina esclusivamente immagini orfane "
        "ad alta certezza. Senza parametri simula soltanto."
    )
)
parser.add_argument(
    "--execute",
    action="store_true",
    help="Esegue realmente la cancellazione.",
)
parser.add_argument(
    "--confirm",
    default="",
    help="Conferma testuale richiesta insieme a --execute.",
)
args = parser.parse_args()

if args.execute and args.confirm != CONFERMA_RICHIESTA:
    raise SystemExit(
        "BLOCCATO: conferma mancante o errata. "
        "Nessun file eliminato."
    )

pattern_sicuri = [
    re.compile(
        r"^uploads/profili/revisioni/"
        r"utente_\d+_(?:foto_profilo|copertina)_pending_"
        r"[0-9a-f]{32}\.[A-Za-z0-9]+$"
    ),
    re.compile(
        r"^uploads/profili/galleria/"
        r"(?:u\d+_[0-9a-f]{32}|"
        r"utente_\d+_galleria_pending_[0-9a-f]{32})"
        r"\.[A-Za-z0-9]+$"
    ),
    re.compile(
        r"^uploads/annunci/"
        r"[0-9a-f]{32}_.+\.[A-Za-z0-9]+$"
    ),
]

upload_root = Path(
    os.getenv("UPLOAD_BASE_DIR", "/uploads")
).resolve()

limite_temporale = time.time() - (
    GIORNI_MINIMI * 24 * 60 * 60
)


def riferimenti_database_freschi():
    riferimenti, _, _ = leggi_riferimenti_database()
    return aggiungi_thumbnail_derivate(riferimenti)


riferimenti_iniziali = riferimenti_database_freschi()
immagini, _, _ = scansiona_immagini(upload_root)
orfane = set(immagini) - riferimenti_iniziali

candidate = []

for percorso_db in orfane:
    if not any(
        pattern.fullmatch(percorso_db)
        for pattern in pattern_sicuri
    ):
        continue

    parti = PurePosixPath(percorso_db).parts

    if len(parti) < 2 or parti[0] != "uploads":
        continue

    percorso_non_risolto = upload_root.joinpath(
        *parti[1:]
    )

    try:
        if percorso_non_risolto.is_symlink():
            continue

        percorso = percorso_non_risolto.resolve()
        percorso.relative_to(upload_root)
        statistiche = percorso.stat()
    except (OSError, ValueError):
        continue

    if statistiche.st_mtime > limite_temporale:
        continue

    candidate.append({
        "percorso_db": percorso_db,
        "percorso": percorso,
        "dimensione": statistiche.st_size,
        "modifica_ns": statistiche.st_mtime_ns,
    })

candidate.sort(
    key=lambda elemento: elemento["percorso_db"]
)

spazio_totale = sum(
    elemento["dimensione"]
    for elemento in candidate
)

print("CONTROLLO FINALE IMMAGINI ORFANE SICURE")
print(f"File trovati: {len(candidate)}")
print(
    "Spazio rilevato: "
    f"{dimensione_leggibile(spazio_totale)}"
)

if len(candidate) != NUMERO_ATTESO:
    raise SystemExit(
        "BLOCCATO: il numero dei file non coincide "
        "con la simulazione. Nessun file eliminato."
    )

if not (
    SPAZIO_MINIMO_ATTESO
    <= spazio_totale
    <= SPAZIO_MASSIMO_ATTESO
):
    raise SystemExit(
        "BLOCCATO: lo spazio non coincide con la "
        "simulazione. Nessun file eliminato."
    )

# Controllo conservativo contro eventuali riferimenti
# scritti direttamente nei sorgenti del progetto.
estensioni_sorgenti = {
    ".py",
    ".html",
    ".js",
    ".css",
}

riferimenti_hardcoded = set()
percorsi_candidati = {
    elemento["percorso_db"]
    for elemento in candidate
}

for sorgente in Path(".").rglob("*"):
    if not sorgente.is_file():
        continue

    if sorgente.suffix.lower() not in estensioni_sorgenti:
        continue

    if any(
        parte in {".git", "venv", "env", "__pycache__"}
        for parte in sorgente.parts
    ):
        continue

    try:
        contenuto = sorgente.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        continue

    for percorso_db in percorsi_candidati:
        if percorso_db in contenuto:
            riferimenti_hardcoded.add(percorso_db)

if riferimenti_hardcoded:
    print("Riferimenti trovati nei sorgenti:")

    for percorso_db in sorted(riferimenti_hardcoded):
        print(percorso_db)

    raise SystemExit(
        "BLOCCATO: trovati riferimenti nei sorgenti. "
        "Nessun file eliminato."
    )

# Seconda lettura del database immediatamente prima
# dell'operazione irreversibile.
riferimenti_finali = riferimenti_database_freschi()

diventate_referenziate = [
    elemento["percorso_db"]
    for elemento in candidate
    if elemento["percorso_db"] in riferimenti_finali
]

if diventate_referenziate:
    print("File diventati referenziati:")

    for percorso_db in diventate_referenziate:
        print(percorso_db)

    raise SystemExit(
        "BLOCCATO: alcuni file sono diventati "
        "referenziati. Nessun file eliminato."
    )

# Verifica tutti i file prima di cancellarne anche uno.
for elemento in candidate:
    percorso = elemento["percorso"]

    try:
        statistiche = percorso.stat()
    except OSError:
        raise SystemExit(
            "BLOCCATO: un file non è più presente. "
            "Nessun file eliminato."
        )

    if (
        statistiche.st_size != elemento["dimensione"]
        or statistiche.st_mtime_ns != elemento["modifica_ns"]
    ):
        raise SystemExit(
            "BLOCCATO: un file è cambiato durante "
            "il controllo. Nessun file eliminato."
        )

if not args.execute:
    print()
    print(
        "SIMULAZIONE COMPLETATA: "
        "tutti i controlli sono superati."
    )
    print("Nessun file è stato eliminato.")
    raise SystemExit(0)

eliminati = 0
spazio_eliminato = 0

for elemento in candidate:
    try:
        elemento["percorso"].unlink()
    except OSError as errore:
        print(
            "ERRORE durante la rimozione di "
            f"{elemento['percorso_db']}: {errore}"
        )
        break

    eliminati += 1
    spazio_eliminato += elemento["dimensione"]
    print("ELIMINATA:", elemento["percorso_db"])

print()
print(f"File eliminati: {eliminati}")
print(
    "Spazio recuperato: "
    f"{dimensione_leggibile(spazio_eliminato)}"
)
print("Il database non è stato modificato.")
