import unittest
from pathlib import Path


class AnonymousAnalyticsLegalCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.privacy = (cls.root / "templates" / "privacy.html").read_text(
            encoding="utf-8"
        )
        cls.cookies = (
            cls.root / "templates" / "cookie_policy.html"
        ).read_text(encoding="utf-8")

    def test_privacy_keeps_registered_and_anonymous_metrics_distinct(self):
        for marker in (
            "utenti registrati unici",
            "metrica resta separata da quella anonima",
            "visita anonima per quella sessione o browser",
            "non equivale al numero certo di persone uniche",
            "oltre gli ultimi 30 giorni",
            "eliminate insieme all’account",
        ):
            self.assertIn(marker, self.privacy)

    def test_privacy_discloses_minimised_anonymous_counter(self):
        for marker in (
            "Nella tabella statistica anonima vengono salvati soltanto il giorno e il conteggio aggregato",
            "senza indirizzo IP, user-agent, URL o pagine visitate",
            "senza un identificatore anonimo o della sessione",
            "non viene copiato nella tabella statistica",
        ):
            self.assertIn(marker, self.privacy)

    def test_cookie_policy_explains_first_party_session_count(self):
        for marker in (
            "Conteggio aggregato delle visite anonime",
            "sessione tecnica già esistente",
            "una visita per quella sessione o browser in ciascun giorno",
            "Non viene creato un cookie autonomo di profilazione o marketing",
            "non rappresenta persone uniche certe",
            "non utilizza per questo conteggio servizi statistici di terze parti",
        ):
            self.assertIn(marker, self.cookies)

    def test_cookie_policy_discloses_minimisation_and_retention(self):
        for marker in (
            "soltanto il giorno e il conteggio aggregato",
            "Non vengono memorizzati indirizzo IP, user-agent, URL o pagine visitate",
            "né identificatori anonimi o della sessione",
            "eliminati oltre gli ultimi 30 giorni",
            "separati dalla metrica degli utenti registrati unici",
        ):
            self.assertIn(marker, self.cookies)


if __name__ == "__main__":
    unittest.main()
