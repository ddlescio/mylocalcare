import argparse
import os
import sqlite3
from pathlib import Path, PurePosixPath

import psycopg2

from image_utils import (
    crea_thumbnail_cerca,
    percorso_thumbnail_relativo,
)


def leggi_foto_profilo():
    database_url = os.getenv("DATABASE_URL", "").strip()

    if database_url:
        conn = psycopg2.connect(
            database_url,
            connect_timeout=8,
            sslmode="require",
        )

        try:
            conn.set_session(
                readonly=True,
                autocommit=True,
            )

            cur = conn.cursor()
            cur.execute("""
                SELECT id, foto_profilo
                FROM utenti
                WHERE foto_profilo IS NOT NULL
                  AND TRIM(foto_profilo) <> ''
                ORDER BY id
            """)

            return cur.fetchall()

        finally:
            conn.close()

    database_path = Path("database.db").resolve()

    if not database_path.is_file():
        raise RuntimeError(
            f"Database SQLite non trovato: {database_path}"
        )

    conn = sqlite3.connect(
        f"file:{database_path.as_posix()}?mode=ro",
        uri=True,
    )

    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, foto_profilo
            FROM utenti
            WHERE foto_profilo IS NOT NULL
              AND TRIM(foto_profilo) <> ''
            ORDER BY id
        """)

        return cur.fetchall()

    finally:
        conn.close()


def risolvi_percorso_upload(upload_root, percorso_relativo):
    valore = (
        str(percorso_relativo or "")
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

    return upload_root.joinpath(
        *percorso.parts[1:]
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Genera esclusivamente le miniature mancanti "
            "delle foto profilo approvate."
        )
    )

    parser.add_argument(
        "--execute",
        action="store_true",
        help=(
            "Crea realmente le miniature. "
            "Senza questa opzione viene eseguita soltanto la simulazione."
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help=(
            "Numero massimo di miniature da creare. "
            "0 significa nessun limite."
        ),
    )

    args = parser.parse_args()

    if args.limit < 0:
        raise RuntimeError(
            "--limit non può essere negativo."
        )

    upload_root = Path(
        os.getenv("UPLOAD_BASE_DIR", "/uploads")
    ).resolve()

    if not upload_root.is_dir():
        raise RuntimeError(
            f"Cartella upload non trovata: {upload_root}"
        )

    righe = leggi_foto_profilo()

    percorsi_gia_visti = set()
    candidati = []

    totali = 0
    duplicati = 0
    percorsi_non_validi = 0
    originali_mancanti = 0
    thumbnail_esistenti = 0

    for user_id, foto_profilo in righe:
        totali += 1

        percorso_originale = str(
            foto_profilo or ""
        ).strip()

        if percorso_originale in percorsi_gia_visti:
            duplicati += 1
            continue

        percorsi_gia_visti.add(percorso_originale)

        percorso_thumbnail = percorso_thumbnail_relativo(
            percorso_originale
        )

        originale_assoluto = risolvi_percorso_upload(
            upload_root,
            percorso_originale,
        )

        thumbnail_assoluto = risolvi_percorso_upload(
            upload_root,
            percorso_thumbnail,
        )

        if not originale_assoluto or not thumbnail_assoluto:
            percorsi_non_validi += 1
            continue

        if not originale_assoluto.is_file():
            originali_mancanti += 1
            continue

        if thumbnail_assoluto.is_file():
            thumbnail_esistenti += 1
            continue

        candidati.append(
            (
                user_id,
                originale_assoluto,
                thumbnail_assoluto,
            )
        )

    candidati_totali = len(candidati)

    if args.limit > 0:
        candidati = candidati[:args.limit]

    print(f"Foto profilo nel database: {totali}")
    print(f"Percorsi duplicati: {duplicati}")
    print(f"Percorsi non validi o esterni a uploads: {percorsi_non_validi}")
    print(f"File originali mancanti: {originali_mancanti}")
    print(f"Miniature già esistenti: {thumbnail_esistenti}")
    print(f"Miniature complessivamente mancanti: {candidati_totali}")
    print(f"Miniature selezionate in questa esecuzione: {len(candidati)}")

    if not args.execute:
        print(
            "SIMULAZIONE COMPLETATA: "
            "nessun file è stato creato o modificato."
        )
        return

    create = 0
    errors = 0

    for user_id, originale_assoluto, thumbnail_assoluto in candidati:
        if thumbnail_assoluto.is_file():
            continue

        try:
            crea_thumbnail_cerca(
                percorso_originale_assoluto=str(
                    originale_assoluto
                ),
                percorso_thumbnail_assoluto=str(
                    thumbnail_assoluto
                ),
                dimensioni_massime=(960, 960),
                qualita=76,
            )

            create += 1

        except Exception as e:
            errors += 1
            print(
                "ERRORE thumbnail foto profilo "
                f"utente {user_id}: {e}"
            )

    print(f"Miniature create: {create}")
    print(f"Errori: {errors}")

    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
