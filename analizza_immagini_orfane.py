import argparse
import json
import os
import sqlite3
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import psycopg2



ESTENSIONI_IMMAGINI = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".heic",
    ".heif",
    ".avif",
    ".gif",
    ".bmp",
    ".tif",
    ".tiff",
    ".jfif",
    ".mpo",
}

def percorso_thumbnail_relativo(percorso_originale):
    valore = (
        str(percorso_originale or "")
        .strip()
        .replace("\\", "/")
    )

    if not valore:
        return None

    percorso = PurePosixPath(valore)

    if (
        percorso.is_absolute()
        or ".." in percorso.parts
        or len(percorso.parts) < 2
        or percorso.parts[0] != "uploads"
    ):
        return None

    nome_thumbnail = (
        f"{percorso.stem}_cerca.webp"
    )

    return str(
        PurePosixPath(
            "uploads",
            "thumbnails",
            *percorso.parts[1:-1],
            nome_thumbnail,
        )
    )

def normalizza_percorso_upload(valore):
    testo = (
        str(valore or "")
        .strip()
        .replace("\\", "/")
    )

    if not testo or "\x00" in testo:
        return None

    parsed = urlsplit(testo)

    if parsed.scheme or parsed.netloc:
        return None

    testo = unquote(parsed.path or testo)

    while testo.startswith("./"):
        testo = testo[2:]

    if testo.startswith("/static/"):
        testo = testo[len("/static/"):]
    elif testo.startswith("static/"):
        testo = testo[len("static/"):]

    testo = testo.lstrip("/")
    percorso = PurePosixPath(testo)

    if (
        ".." in percorso.parts
        or len(percorso.parts) < 2
        or percorso.parts[0] != "uploads"
    ):
        return None

    return str(percorso)


def estrai_lista_percorsi(valore):
    if not valore:
        return []

    if isinstance(valore, (list, tuple, set)):
        elementi = valore
    else:
        testo = str(valore).strip()

        if not testo:
            return []

        parsed = None

        if testo.startswith("["):
            try:
                parsed = json.loads(testo)
            except (TypeError, ValueError):
                parsed = None

        if isinstance(parsed, list):
            elementi = parsed
        else:
            elementi = testo.split(",")

    risultato = []

    for elemento in elementi:
        elemento = (
            str(elemento or "")
            .strip()
            .strip("[]")
            .strip()
            .strip("\"'")
            .strip()
        )

        if elemento:
            risultato.append(elemento)

    return risultato


def valori_revisione_immagine(campo, valore):
    if campo == "foto_galleria":
        return estrai_lista_percorsi(valore)

    return [valore] if valore else []


def aggiungi_percorso(destinazione, valore, percorsi_invalidi):
    percorso = normalizza_percorso_upload(valore)

    if percorso:
        destinazione.add(percorso)
        return

    testo = str(valore or "").strip()

    if testo and "uploads" in testo.lower():
        percorsi_invalidi.add(testo)


def aggiungi_valori(
    destinazione,
    valori,
    percorsi_invalidi,
):
    for valore in valori or []:
        aggiungi_percorso(
            destinazione,
            valore,
            percorsi_invalidi,
        )


def aggiungi_thumbnail_derivate(percorsi_originali):
    risultato = set(percorsi_originali)

    for percorso in percorsi_originali:
        if percorso.startswith("uploads/thumbnails/"):
            continue

        thumbnail = percorso_thumbnail_relativo(percorso)

        if thumbnail:
            risultato.add(thumbnail)

    return risultato


def apri_database_sola_lettura():
    database_url = os.getenv("DATABASE_URL", "").strip()

    if database_url:
        conn = psycopg2.connect(
            database_url,
            connect_timeout=8,
            sslmode="require",
        )

        conn.set_session(
            readonly=True,
            autocommit=True,
        )

        return conn

    database_path = Path("database.db").resolve()

    if not database_path.is_file():
        raise RuntimeError(
            f"Database SQLite non trovato: {database_path}"
        )

    return sqlite3.connect(
        f"file:{database_path.as_posix()}?mode=ro&immutable=1",
        uri=True,
    )


def leggi_riferimenti_database():
    riferimenti_totali = set()
    riferimenti_attivi = set()
    percorsi_invalidi = set()
    utenti_eliminati = set()

    conn = apri_database_sola_lettura()

    try:
        cur = conn.cursor()

        # Profili utente.
        cur.execute("""
            SELECT
                id,
                username,
                eliminato,
                foto_profilo,
                copertina,
                foto_galleria
            FROM utenti
        """)

        for (
            user_id,
            username,
            eliminato,
            foto_profilo,
            copertina,
            foto_galleria,
        ) in cur.fetchall():
            username_normalizzato = str(
                username or ""
            ).strip().lower()

            account_eliminato = (
                int(eliminato or 0) == 1
                or username_normalizzato.startswith(
                    "utente_eliminato_"
                )
            )

            if account_eliminato:
                utenti_eliminati.add(user_id)

            valori = [
                foto_profilo,
                copertina,
                *estrai_lista_percorsi(
                    foto_galleria
                ),
            ]

            aggiungi_valori(
                riferimenti_totali,
                valori,
                percorsi_invalidi,
            )

            if not account_eliminato:
                aggiungi_valori(
                    riferimenti_attivi,
                    valori,
                    percorsi_invalidi,
                )

        # Revisioni profilo.
        cur.execute("""
            SELECT
                rp.utente_id,
                rp.campo,
                rp.testo_precedente,
                rp.testo_proposto,
                rp.stato,

                EXISTS (
                    SELECT 1
                    FROM revisioni_profilo approvata
                    WHERE approvata.utente_id = rp.utente_id
                      AND approvata.campo = rp.campo
                      AND approvata.stato = 'approvata'
                      AND approvata.data_decisione IS NOT NULL
                      AND rp.data_decisione IS NOT NULL
                      AND approvata.data_decisione > rp.data_decisione
                ) AS ha_approvazione_successiva

            FROM revisioni_profilo rp
            WHERE rp.campo IN (
                'foto_profilo',
                'copertina',
                'foto_galleria'
            )
        """)

        for (
            user_id,
            campo,
            testo_precedente,
            testo_proposto,
            stato,
            ha_approvazione_successiva,
        ) in cur.fetchall():
            precedenti = valori_revisione_immagine(
                campo,
                testo_precedente,
            )
            proposti = valori_revisione_immagine(
                campo,
                testo_proposto,
            )

            aggiungi_valori(
                riferimenti_totali,
                precedenti + proposti,
                percorsi_invalidi,
            )

            if user_id in utenti_eliminati:
                continue

            stato = str(stato or "").strip().lower()

            if stato == "in_attesa":
                aggiungi_valori(
                    riferimenti_attivi,
                    precedenti + proposti,
                    percorsi_invalidi,
                )

            elif (
                stato == "rifiutata"
                and not ha_approvazione_successiva
            ):
                # La proposta rifiutata resta come prova soltanto
                # finché non viene approvata una modifica successiva
                # dello stesso campo.
                aggiungi_valori(
                    riferimenti_attivi,
                    proposti,
                    percorsi_invalidi,
                )

            # Le revisioni approvate non proteggono da sole
            # vecchie immagini: quella attualmente pubblica
            # è già presente nella tabella utenti.

        # Annunci.
        cur.execute("""
            SELECT
                stato,
                media,
                foto_card
            FROM annunci
        """)

        for stato, media, foto_card in cur.fetchall():
            valori = [
                *estrai_lista_percorsi(media),
                foto_card,
            ]

            aggiungi_valori(
                riferimenti_totali,
                valori,
                percorsi_invalidi,
            )

            if str(stato or "").strip().lower() != "eliminato":
                aggiungi_valori(
                    riferimenti_attivi,
                    valori,
                    percorsi_invalidi,
                )

        # Vecchia tabella operatori: l'applicazione può ancora
        # mostrare questi record senza applicare filtri di visibilità.
        # Per prudenza consideriamo attiva ogni foto ancora collegata.
        cur.execute("""
            SELECT foto_profilo
            FROM operatori
            WHERE foto_profilo IS NOT NULL
              AND TRIM(foto_profilo) <> ''
        """)

        for (foto_profilo,) in cur.fetchall():
            aggiungi_percorso(
                riferimenti_totali,
                foto_profilo,
                percorsi_invalidi,
            )

            aggiungi_percorso(
                riferimenti_attivi,
                foto_profilo,
                percorsi_invalidi,
            )

    finally:
        conn.close()

    return (
        riferimenti_totali,
        riferimenti_attivi,
        percorsi_invalidi,
    )


def scansiona_immagini(upload_root):
    immagini = {}
    file_non_immagine = 0
    collegamenti_simbolici = 0

    for percorso in upload_root.rglob("*"):
        if percorso.is_symlink():
            collegamenti_simbolici += 1
            continue

        if not percorso.is_file():
            continue

        if percorso.suffix.lower() not in ESTENSIONI_IMMAGINI:
            file_non_immagine += 1
            continue

        try:
            percorso_risolto = percorso.resolve()
            relativo = percorso_risolto.relative_to(
                upload_root
            )
            dimensione = percorso_risolto.stat().st_size
        except (OSError, ValueError):
            continue

        percorso_db = str(
            PurePosixPath(
                "uploads",
                *relativo.parts,
            )
        )

        immagini[percorso_db] = dimensione

    return (
        immagini,
        file_non_immagine,
        collegamenti_simbolici,
    )


def dimensione_leggibile(numero_byte):
    valore = float(numero_byte)

    for unita in ("B", "KB", "MB", "GB", "TB"):
        if valore < 1024 or unita == "TB":
            return f"{valore:.1f} {unita}"

        valore /= 1024

    return f"{numero_byte} B"


def somma_dimensioni(percorsi, immagini):
    return sum(
        immagini.get(percorso, 0)
        for percorso in percorsi
    )


def stampa_dettagli(
    titolo,
    percorsi,
    immagini,
    limite,
):
    print()
    print(titolo)

    ordinati = sorted(
        percorsi,
        key=lambda percorso: (
            -immagini.get(percorso, 0),
            percorso,
        ),
    )

    if not ordinati:
        print("  Nessuno.")
        return

    for percorso in ordinati[:limite]:
        print(
            "  "
            f"{dimensione_leggibile(immagini[percorso]):>10}  "
            f"{percorso}"
        )

    if len(ordinati) > limite:
        print(
            f"  ... altri {len(ordinati) - limite} "
            "percorsi non mostrati."
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analizza in sola lettura le immagini presenti "
            "nella cartella uploads."
        )
    )

    parser.add_argument(
        "--show",
        type=int,
        default=50,
        help=(
            "Numero massimo di percorsi mostrati "
            "per ogni gruppo. Valore predefinito: 50."
        ),
    )

    args = parser.parse_args()

    if args.show < 0:
        raise RuntimeError(
            "--show non può essere negativo."
        )

    upload_root = Path(
        os.getenv("UPLOAD_BASE_DIR", "/uploads")
    ).resolve()

    if not upload_root.is_dir():
        raise RuntimeError(
            f"Cartella upload non trovata: {upload_root}"
        )

    (
        riferimenti_originali_totali,
        riferimenti_originali_attivi,
        percorsi_invalidi,
    ) = leggi_riferimenti_database()

    riferimenti_totali = aggiungi_thumbnail_derivate(
        riferimenti_originali_totali
    )
    riferimenti_attivi = aggiungi_thumbnail_derivate(
        riferimenti_originali_attivi
    )

    (
        immagini,
        file_non_immagine,
        collegamenti_simbolici,
    ) = scansiona_immagini(upload_root)

    percorsi_presenti = set(immagini)

    immagini_orfane = (
        percorsi_presenti
        - riferimenti_totali
    )

    immagini_solo_storiche = (
        percorsi_presenti
        & riferimenti_totali
        - riferimenti_attivi
    )

    riferimenti_attivi_mancanti = (
        riferimenti_originali_attivi
        - percorsi_presenti
    )

    print("ANALISI IMMAGINI IN SOLA LETTURA")
    print(f"Cartella analizzata: {upload_root}")
    print(f"Immagini presenti sul disco: {len(immagini)}")
    print(
        "Spazio occupato dalle immagini: "
        f"{dimensione_leggibile(sum(immagini.values()))}"
    )
    print(
        "Riferimenti originali complessivi nel database: "
        f"{len(riferimenti_originali_totali)}"
    )
    print(
        "Riferimenti originali ancora attivi: "
        f"{len(riferimenti_originali_attivi)}"
    )
    print(
        "Immagini senza alcun riferimento nel database: "
        f"{len(immagini_orfane)} "
        f"({dimensione_leggibile(somma_dimensioni(immagini_orfane, immagini))})"
    )
    print(
        "Immagini collegate soltanto a dati storici/eliminati: "
        f"{len(immagini_solo_storiche)} "
        f"({dimensione_leggibile(somma_dimensioni(immagini_solo_storiche, immagini))})"
    )
    print(
        "Riferimenti attivi con originale mancante: "
        f"{len(riferimenti_attivi_mancanti)}"
    )
    print(
        "Percorsi uploads non validi nel database: "
        f"{len(percorsi_invalidi)}"
    )
    print(f"File non immagine ignorati: {file_non_immagine}")
    print(
        "Collegamenti simbolici ignorati: "
        f"{collegamenti_simbolici}"
    )

    stampa_dettagli(
        "IMMAGINI SENZA RIFERIMENTI:",
        immagini_orfane,
        immagini,
        args.show,
    )

    stampa_dettagli(
        "IMMAGINI COLLEGATE SOLO A DATI STORICI/ELIMINATI:",
        immagini_solo_storiche,
        immagini,
        args.show,
    )

    print()
    print("RIFERIMENTI ATTIVI CON ORIGINALE MANCANTE:")

    if riferimenti_attivi_mancanti:
        for percorso in sorted(
            riferimenti_attivi_mancanti
        )[:args.show]:
            print(f"  {percorso}")
    else:
        print("  Nessuno.")

    print()
    print("PERCORSI UPLOADS NON VALIDI NEL DATABASE:")

    if percorsi_invalidi:
        for percorso in sorted(
            percorsi_invalidi
        )[:args.show]:
            print(f"  {percorso}")
    else:
        print("  Nessuno.")

    print()
    print(
        "ANALISI COMPLETATA: "
        "nessun file e nessun dato del database "
        "sono stati creati, modificati o eliminati."
    )


if __name__ == "__main__":
    main()
