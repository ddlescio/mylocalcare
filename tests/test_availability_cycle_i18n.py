import unittest

from i18n import translate_source
from i18n_catalog import PHRASE_ROWS


class AvailabilityCycleTranslationsTest(unittest.TestCase):
    SOURCES = (
        "Nuova disponibilità: conferma i tuoi annunci",
        (
            "MyLocalCare ha introdotto la disponibilità aggiornata per "
            "rendere le ricerche più affidabili e aumentare le tue possibilità "
            "di ricevere contatti. Controlla i dati dei tuoi servizi e "
            "confermali."
        ),
        "Promemoria: aggiorna la tua disponibilità",
        (
            "La disponibilità aggiornata rende MyLocalCare più affidabile e "
            "aumenta le possibilità di ricevere contatti. Conferma i tuoi "
            "annunci: bastano pochi secondi."
        ),
        "Conferma la disponibilità per restare visibile",
        (
            "Per offrire ricerche più affidabili, MyLocalCare indica quali "
            "annunci hanno una disponibilità aggiornata. Conferma ora per "
            "mantenere i tuoi annunci visibili e aumentare le possibilità "
            "di ricevere contatti."
        ),
        "Ultimo avviso: conferma la disponibilità",
        (
            "Per mantenere le ricerche affidabili, i tuoi annunci ora "
            "risultano non disponibili e hanno priorità ridotta. Conferma "
            "entro 7 giorni per riattivarli ed evitare l'archiviazione "
            "automatica."
        ),
        "Annuncio archiviato per disponibilità non confermata",
        (
            "L'annuncio è stato archiviato e non compare più nei risultati. "
            "Contenuti e foto sono conservati: riconferma la disponibilità "
            "per riattivarlo."
        ),
        "Controlla la disponibilità dei tuoi annunci",
        "Apri il tuo profilo e conferma la disponibilità aggiornata.",
    )

    ORDINARY_SOURCES = (
        "La tua disponibilità sta per scadere",
        (
            "La tua disponibilità scadrà tra 5 giorni. Controlla i dati "
            "già salvati: puoi riconfermarli così come sono oppure modificarli."
        ),
        "Rinnova la tua disponibilità",
        (
            "La tua disponibilità è scaduta. Riconferma i dati già salvati "
            "oppure aggiornali per mantenerla attuale."
        ),
        "Ultimo avviso: rinnova la disponibilità",
        (
            "La tua disponibilità è scaduta da 7 giorni. I tuoi annunci ora "
            "risultano non disponibili e hanno priorità ridotta. Riconferma "
            "entro 7 giorni per evitare l’archiviazione automatica."
        ),
        "Controlla disponibilità",
    )

    def test_every_cycle_copy_has_all_supported_languages(self):
        rows = {row[0]: row for row in PHRASE_ROWS}

        for source in self.SOURCES + self.ORDINARY_SOURCES:
            self.assertIn(source, rows, source)
            self.assertEqual(len(rows[source]), 5, source)
            for translation in rows[source]:
                self.assertTrue(translation.strip(), source)
            for language in ("ro", "uk", "fil"):
                self.assertNotEqual(
                    translate_source(source, language),
                    source,
                    (source, language),
                )

    def test_cycle_copy_is_translated_in_every_catalog_language(self):
        for source in self.SOURCES + self.ORDINARY_SOURCES:
            for language in ("en", "fr", "es", "de", "ro", "uk", "fil"):
                self.assertNotEqual(
                    translate_source(source, language),
                    source,
                    (source, language),
                )


if __name__ == "__main__":
    unittest.main()
