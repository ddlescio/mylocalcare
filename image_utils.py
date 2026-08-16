import os
import re
import uuid
from pathlib import PurePosixPath

from PIL import Image, ImageOps, UnidentifiedImageError


MAX_IMAGE_PIXELS_LOCALCARE = 60_000_000


class ErroreImmagine(ValueError):
    """Errore controllato durante la lettura o la conversione di un'immagine."""


class ImmagineAnimata(ErroreImmagine):
    """Segnala un'immagine animata, che non è consentita."""

def _prefisso_sicuro(prefisso):
    valore = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(prefisso or "immagine"))
    return valore.strip("_") or "immagine"


def _apri_e_prepara_immagine(
    sorgente,
    dimensioni_massime,
    consenti_animata=False
):
    immagine_originale = None
    chiudi_originale = isinstance(sorgente, (str, bytes, os.PathLike))

    try:
        immagine_originale = Image.open(sorgente)
        formato_originale = (immagine_originale.format or "").upper()
        formato_mpo = formato_originale == "MPO"

        if formato_originale not in {"JPEG", "PNG", "WEBP", "MPO"}:
            raise ErroreImmagine(
                "Formato immagine non consentito. Usa JPG, PNG o WEBP."
            )

        larghezza, altezza = immagine_originale.size

        if larghezza <= 0 or altezza <= 0:
            raise ErroreImmagine("Dimensioni immagine non valide.")

        if larghezza * altezza > MAX_IMAGE_PIXELS_LOCALCARE:
            raise ErroreImmagine("Immagine troppo grande.")

        if (
            getattr(immagine_originale, "is_animated", False)
            and not consenti_animata
            and not formato_mpo
        ):
            raise ImmagineAnimata(
                "Le immagini animate non sono consentite."
            )

        if (
            formato_mpo
            or getattr(immagine_originale, "is_animated", False)
        ):
            immagine_originale.seek(0)

        immagine = ImageOps.exif_transpose(immagine_originale)
        immagine.load()

    except ErroreImmagine:
        raise

    except (
        UnidentifiedImageError,
        Image.DecompressionBombError,
        OSError,
        SyntaxError,
        ValueError,
    ) as exc:
        raise ErroreImmagine(
            "Il file non è un'immagine valida o supportata."
        ) from exc

    finally:
        if immagine_originale is not None and chiudi_originale:
            try:
                immagine_originale.close()
            except Exception:
                pass

    ha_trasparenza = (
        immagine.mode in ("RGBA", "LA")
        or (
            immagine.mode == "P"
            and "transparency" in immagine.info
        )
    )

    modo_destinazione = "RGBA" if ha_trasparenza else "RGB"

    immagine_convertita = immagine.convert(modo_destinazione)
    immagine.close()
    immagine = immagine_convertita

    immagine.thumbnail(
        tuple(dimensioni_massime),
        Image.Resampling.LANCZOS
    )

    return immagine


def _salva_webp_atomico(immagine, percorso_finale, qualita):
    directory = os.path.dirname(percorso_finale)
    os.makedirs(directory, exist_ok=True)

    percorso_temporaneo = os.path.join(
        directory,
        f".tmp_{uuid.uuid4().hex}.webp",
    )

    try:
        opzioni_salvataggio = {
            "format": "WEBP",
            "quality": int(qualita),
            "method": 6,
        }

        profilo_colore = immagine.info.get("icc_profile")

        if profilo_colore:
            opzioni_salvataggio["icc_profile"] = profilo_colore

        immagine.save(
            percorso_temporaneo,
            **opzioni_salvataggio
        )

        os.replace(
            percorso_temporaneo,
            percorso_finale
        )

    finally:
        if os.path.exists(percorso_temporaneo):
            try:
                os.remove(percorso_temporaneo)
            except OSError:
                pass


def salva_immagine_ottimizzata(
    file_storage,
    directory_destinazione,
    prefisso,
    dimensioni_massime,
    qualita=82,
):
    if not file_storage:
        raise ErroreImmagine("File immagine mancante.")

    stream = getattr(
        file_storage,
        "stream",
        file_storage
    )

    try:
        stream.seek(0)
    except (AttributeError, OSError, ValueError):
        pass

    try:
        immagine = _apri_e_prepara_immagine(
            stream,
            dimensioni_massime=dimensioni_massime,
            consenti_animata=False,
        )

        nome_file = (
            f"{_prefisso_sicuro(prefisso)}_"
            f"{uuid.uuid4().hex}.webp"
        )

        percorso_finale = os.path.join(
            directory_destinazione,
            nome_file
        )

        try:
            _salva_webp_atomico(
                immagine,
                percorso_finale,
                qualita
            )

            return nome_file

        finally:
            immagine.close()

    finally:
        try:
            stream.seek(0)
        except (AttributeError, OSError, ValueError):
            pass


def percorso_thumbnail_relativo(percorso_originale):
    valore = (
        str(percorso_originale or "")
        .strip()
        .replace("\\", "/")
    )

    if not valore:
        return None

    percorso = PurePosixPath(valore)

    if percorso.is_absolute() or ".." in percorso.parts:
        return None

    if (
        len(percorso.parts) < 2
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


def crea_thumbnail_cerca(
    percorso_originale_assoluto,
    percorso_thumbnail_assoluto,
    dimensioni_massime=(960, 960),
    qualita=76,
):
    immagine = _apri_e_prepara_immagine(
        percorso_originale_assoluto,
        dimensioni_massime=dimensioni_massime,
        consenti_animata=True,
    )

    try:
        _salva_webp_atomico(
            immagine,
            percorso_thumbnail_assoluto,
            qualita,
        )

    finally:
        immagine.close()


def scegli_immagine_cerca(
    static_folder,
    percorso_originale
):
    percorso_originale = str(
        percorso_originale or ""
    ).strip()

    if not percorso_originale:
        return percorso_originale

    percorso_thumbnail = percorso_thumbnail_relativo(
        percorso_originale
    )

    if not percorso_thumbnail:
        return percorso_originale

    percorso_assoluto = os.path.join(
        static_folder,
        *PurePosixPath(percorso_thumbnail).parts,
    )

    if os.path.isfile(percorso_assoluto):
        return percorso_thumbnail

    return percorso_originale
