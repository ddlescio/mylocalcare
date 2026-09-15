import unittest
from datetime import datetime, timedelta, timezone

from chat_risk import segnalazione_chat_controllata, valuta_rischio_chat


class ChatRiskTest(unittest.TestCase):
    def test_attivita_normale_non_viene_segnalata(self):
        risultato = valuta_rischio_chat({
            "nuove_chat_24h": 2,
            "nuove_chat_7g": 7,
            "nuove_chat_30g": 18,
            "giorni_attivi_7g": 3,
            "regioni_contattate_7g": 2,
            "province_contattate_7g": 3,
            "senza_risposta_7g": 4,
        })

        self.assertFalse(risultato["sospetto"])
        self.assertEqual(risultato["motivi"], [])

    def test_picco_giornaliero_viene_segnalato(self):
        risultato = valuta_rischio_chat({"nuove_chat_24h": 10})

        self.assertTrue(risultato["sospetto"])
        self.assertIn("24 ore", risultato["motivo"])

    def test_attivita_continuativa_viene_segnalata(self):
        risultato = valuta_rischio_chat({
            "nuove_chat_7g": 16,
            "giorni_attivi_7g": 4,
        })

        self.assertTrue(risultato["sospetto"])
        self.assertIn("continuativa", risultato["motivo"])

    def test_dispersione_multiregione_viene_segnalata(self):
        risultato = valuta_rischio_chat({
            "nuove_chat_7g": 10,
            "regioni_contattate_7g": 4,
        })

        self.assertTrue(risultato["sospetto"])
        self.assertIn("4 regioni", risultato["motivo"])

    def test_molte_chat_senza_risposta_vengono_segnalate(self):
        risultato = valuta_rischio_chat({
            "nuove_chat_7g": 12,
            "senza_risposta_7g": 12,
        })

        self.assertTrue(risultato["sospetto"])
        self.assertIn("senza risposta", risultato["motivo"])

    def test_due_blocchi_ricevuti_vengono_segnalati(self):
        risultato = valuta_rischio_chat({
            "blocchi_ricevuti_30g": 2,
        })

        self.assertTrue(risultato["sospetto"])
        self.assertIn("bloccato da 2 utenti", risultato["motivo"])

    def test_controllo_successivo_all_ultima_attivita_archivia_il_caso(self):
        attivita = datetime(2026, 9, 15, 8, 0, tzinfo=timezone.utc)
        controllo = attivita + timedelta(minutes=5)

        self.assertTrue(segnalazione_chat_controllata(controllo, attivita))

    def test_nuova_attivita_successiva_riapre_il_caso(self):
        controllo = datetime(2026, 9, 15, 8, 0, tzinfo=timezone.utc)
        nuova_attivita = controllo + timedelta(minutes=5)

        self.assertFalse(
            segnalazione_chat_controllata(controllo, nuova_attivita)
        )


if __name__ == "__main__":
    unittest.main()
