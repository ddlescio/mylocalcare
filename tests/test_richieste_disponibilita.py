import copy
import unittest
from pathlib import Path

from richieste_disponibilita import (
    FASCE_RICHIESTA_DISPONIBILITA,
    MAX_GIORNI_PER_RICHIESTA,
    MAX_INTERVALLI_PER_GIORNO,
    MAX_RICHIESTE_24_ORE,
    MAX_RICHIESTE_7_GIORNI,
    MAX_RICHIESTE_PENDENTI,
    MINUTI_ATTESA_STESSO_ANNUNCIO,
    STATI_RICHIESTA_DISPONIBILITA,
    normalizza_stato_richiesta_disponibilita,
    normalize_richiesta_disponibilita_payload,
    valida_limiti_anti_abuso,
)


ROOT = Path(__file__).resolve().parents[1]


def day(number=1, *, slots=None, intervals=None):
    return {
        "giorno_settimana": number,
        "fasce": [] if slots is None else slots,
        "intervalli": [] if intervals is None else intervals,
    }


def interval(start, end, next_day=False):
    return {
        "ora_inizio": start,
        "ora_fine": end,
        "giorno_successivo": next_day,
    }


class RichiestaDisponibilitaNormalizationTest(unittest.TestCase):
    def test_vocabolari_chiusi(self):
        self.assertEqual(
            STATI_RICHIESTA_DISPONIBILITA,
            (
                "in_attesa",
                "disponibile",
                "non_disponibile",
                "informazioni",
                "scaduta",
            ),
        )
        self.assertEqual(
            FASCE_RICHIESTA_DISPONIBILITA,
            ("mattina", "pomeriggio", "sera", "notte"),
        )

    def test_normalizza_fasce_intervalli_e_giorni_senza_mutare_input(self):
        payload = {
            "giorni": [
                day(5, slots=["notte", "mattina", "notte"]),
                day(2, intervals=[
                    interval("17:00", "18:00"),
                    interval("15:30", "16:30"),
                ]),
                day(
                    3,
                    slots=[" POMERIGGIO "],
                    intervals=[interval("15:30", "18:00")],
                ),
            ],
        }
        original = copy.deepcopy(payload)

        result = normalize_richiesta_disponibilita_payload(payload)

        self.assertEqual(payload, original)
        self.assertEqual(
            [row["giorno_settimana"] for row in result["giorni"]],
            [2, 3, 5],
        )
        self.assertEqual(
            result["giorni"][0]["intervalli"],
            [
                interval("15:30", "16:30"),
                interval("17:00", "18:00"),
            ],
        )
        self.assertEqual(
            result["giorni"][2]["fasce"],
            ["mattina", "notte"],
        )

    def test_accetta_fasce_e_intervalli_nello_stesso_giorno(self):
        result = normalize_richiesta_disponibilita_payload({
            "giorni": [day(
                1,
                slots=["pomeriggio"],
                intervals=[interval("15:30", "18:00")],
            )],
        })
        self.assertEqual(result["giorni"][0]["fasce"], ["pomeriggio"])
        self.assertEqual(
            result["giorni"][0]["intervalli"],
            [interval("15:30", "18:00")],
        )

    def test_accetta_a_chiamata_da_solo(self):
        result = normalize_richiesta_disponibilita_payload({
            "a_chiamata": True,
            "giorni": [],
        })

        self.assertEqual(result, {
            "a_chiamata": True,
            "giorni": [],
        })

    def test_accetta_a_chiamata_insieme_a_giorni_e_orari(self):
        result = normalize_richiesta_disponibilita_payload({
            "a_chiamata": True,
            "giorni": [day(
                4,
                slots=["mattina"],
                intervals=[interval("09:00", "11:00")],
            )],
        })

        self.assertTrue(result["a_chiamata"])
        self.assertEqual(result["giorni"][0]["giorno_settimana"], 4)

    def test_rifiuta_richiesta_senza_giorni_ne_a_chiamata(self):
        for payload in ({}, {"giorni": []}, {"a_chiamata": False, "giorni": []}):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "almeno un giorno"):
                    normalize_richiesta_disponibilita_payload(payload)

    def test_rifiuta_a_chiamata_non_booleano(self):
        for value in (1, 0, "true", None, []):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "deve essere booleano"):
                    normalize_richiesta_disponibilita_payload({
                        "a_chiamata": value,
                        "giorni": [day(1, slots=["mattina"])],
                    })

    def test_accetta_intervallo_notturno_oltre_mezzanotte(self):
        result = normalize_richiesta_disponibilita_payload({
            "giorni": [day(
                6,
                intervals=[interval("22:30", "02:15", True)],
            )],
        })
        self.assertEqual(
            result["giorni"][0]["intervalli"],
            [interval("22:30", "02:15", True)],
        )

    def test_rifiuta_oltre_mezzanotte_senza_flag(self):
        with self.assertRaisesRegex(ValueError, "successiva"):
            normalize_richiesta_disponibilita_payload({
                "giorni": [day(
                    6,
                    intervals=[interval("22:30", "02:15")],
                )],
            })

    def test_rifiuta_flag_giorno_successivo_su_orario_non_notturno(self):
        for value in (
            interval("15:00", "02:00", True),
            interval("22:00", "10:00", True),
            interval("22:00", "23:00", True),
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "notturno"):
                    normalize_richiesta_disponibilita_payload({
                        "giorni": [day(1, intervals=[value])],
                    })

    def test_rifiuta_intervalli_sovrapposti_nello_stesso_giorno(self):
        with self.assertRaisesRegex(ValueError, "sovrapporsi"):
            normalize_richiesta_disponibilita_payload({
                "giorni": [day(1, intervals=[
                    interval("15:30", "18:00"),
                    interval("17:30", "19:00"),
                ])],
            })

    def test_accetta_intervalli_adiacenti(self):
        result = normalize_richiesta_disponibilita_payload({
            "giorni": [day(1, intervals=[
                interval("15:30", "18:00"),
                interval("18:00", "19:00"),
            ])],
        })
        self.assertEqual(len(result["giorni"][0]["intervalli"]), 2)

    def test_rifiuta_sovrapposizione_con_giorno_successivo(self):
        with self.assertRaisesRegex(ValueError, "oltre mezzanotte"):
            normalize_richiesta_disponibilita_payload({
                "giorni": [
                    day(1, intervals=[interval("22:00", "02:00", True)]),
                    day(2, intervals=[interval("01:00", "03:00")]),
                ],
            })

    def test_rifiuta_sovrapposizione_circolare_domenica_lunedi(self):
        with self.assertRaisesRegex(ValueError, "oltre mezzanotte"):
            normalize_richiesta_disponibilita_payload({
                "giorni": [
                    day(1, intervals=[interval("01:00", "03:00")]),
                    day(7, intervals=[interval("22:00", "02:00", True)]),
                ],
            })

    def test_rifiuta_giorno_vuoto_duplicato_o_fuori_intervallo(self):
        invalid = (
            {"giorni": []},
            {"giorni": [day(1)]},
            {"giorni": [day(1, slots=["mattina"]), day(1, slots=["sera"])]},
            {"giorni": [day(0, slots=["mattina"])]},
            {"giorni": [day(8, slots=["mattina"])]},
            {"giorni": [day(True, slots=["mattina"])]},
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    normalize_richiesta_disponibilita_payload(payload)

    def test_rifiuta_formati_orari_e_booleani_non_validi(self):
        for value in (
            interval("9:00", "10:00"),
            interval("09:00", "24:00"),
            interval("09:00", "09:00"),
            {
                "ora_inizio": "22:00",
                "ora_fine": "02:00",
                "giorno_successivo": 1,
            },
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_richiesta_disponibilita_payload({
                        "giorni": [day(1, intervals=[value])],
                    })

    def test_rifiuta_testo_libero_recapiti_e_campi_sconosciuti(self):
        for key, value in (
            ("note", "Chiamami al 3331234567"),
            ("telefono", "+39 3331234567"),
            ("email", "utente@example.com"),
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "non consentiti"):
                    normalize_richiesta_disponibilita_payload({
                        "giorni": [day(1, slots=["mattina"])],
                        key: value,
                    })

        with self.assertRaisesRegex(ValueError, "non consentiti"):
            normalize_richiesta_disponibilita_payload({"giorni": [{
                **day(1, slots=["mattina"]),
                "messaggio": "Scrivimi su WhatsApp",
            }]})

    def test_applica_limiti_strutturali(self):
        too_many_days = [
            day(number, slots=["mattina"])
            for number in range(1, MAX_GIORNI_PER_RICHIESTA + 1)
        ] + [day(1, slots=["sera"])]
        with self.assertRaisesRegex(ValueError, "piu di"):
            normalize_richiesta_disponibilita_payload({
                "giorni": too_many_days,
            })

        too_many_intervals = [
            interval(f"{hour:02d}:00", f"{hour:02d}:30")
            for hour in range(MAX_INTERVALLI_PER_GIORNO + 1)
        ]
        with self.assertRaisesRegex(ValueError, "piu di"):
            normalize_richiesta_disponibilita_payload({
                "giorni": [day(1, intervals=too_many_intervals)],
            })

    def test_normalizza_stati(self):
        self.assertEqual(
            normalizza_stato_richiesta_disponibilita(" DISPONIBILE "),
            "disponibile",
        )
        with self.assertRaises(ValueError):
            normalizza_stato_richiesta_disponibilita("forse")


class RichiestaDisponibilitaAntiAbuseTest(unittest.TestCase):
    def test_accetta_conteggi_sotto_soglia(self):
        result = valida_limiti_anti_abuso(
            richieste_24_ore=MAX_RICHIESTE_24_ORE - 1,
            richieste_7_giorni=MAX_RICHIESTE_7_GIORNI - 1,
            richieste_pendenti=MAX_RICHIESTE_PENDENTI - 1,
            minuti_da_ultima_stesso_annuncio=(
                MINUTI_ATTESA_STESSO_ANNUNCIO
            ),
        )
        self.assertEqual(
            result["richieste_24_ore"],
            MAX_RICHIESTE_24_ORE - 1,
        )

    def test_blocca_richiesta_pendente_duplicata(self):
        with self.assertRaisesRegex(ValueError, "gia una richiesta"):
            valida_limiti_anti_abuso(
                richieste_24_ore=0,
                richieste_7_giorni=0,
                richieste_pendenti=0,
                richiesta_pendente_stesso_annuncio=True,
            )

    def test_blocca_cooldown_e_soglie(self):
        base = {
            "richieste_24_ore": 0,
            "richieste_7_giorni": 0,
            "richieste_pendenti": 0,
        }
        cases = (
            ({
                **base,
                "minuti_da_ultima_stesso_annuncio": (
                    MINUTI_ATTESA_STESSO_ANNUNCIO - 1
                ),
            }, "attendi"),
            ({**base, "richieste_24_ore": MAX_RICHIESTE_24_ORE}, "24 ore"),
            ({
                **base,
                "richieste_7_giorni": MAX_RICHIESTE_7_GIORNI,
            }, "7 giorni"),
            ({
                **base,
                "richieste_pendenti": MAX_RICHIESTE_PENDENTI,
            }, "in attesa"),
        )
        for kwargs, message in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ValueError, message):
                    valida_limiti_anti_abuso(**kwargs)

    def test_rifiuta_conteggi_non_interi_o_negativi(self):
        for invalid in (-1, True, 1.5, "1"):
            with self.subTest(value=invalid):
                with self.assertRaises(ValueError):
                    valida_limiti_anti_abuso(
                        richieste_24_ore=invalid,
                        richieste_7_giorni=0,
                        richieste_pendenti=0,
                    )


class RichiestaDisponibilitaMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = (
            ROOT / "migrations" / "20260925_richieste_disponibilita.sql"
        ).read_text(encoding="utf-8")

    def test_schema_ha_main_e_figlie_con_cascade(self):
        for table in (
            "richieste_disponibilita",
            "richieste_disponibilita_fasce",
            "richieste_disponibilita_intervalli",
        ):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", self.sql)
        self.assertGreaterEqual(self.sql.count("ON DELETE CASCADE"), 5)

    def test_schema_vincola_attori_stati_giorni_e_orari(self):
        self.assertIn("richiedente_id <> offerente_id", self.sql)
        self.assertIn("a_chiamata BOOLEAN NOT NULL DEFAULT FALSE", self.sql)
        self.assertIn("ADD COLUMN IF NOT EXISTS a_chiamata", self.sql)
        self.assertIn("giorno_settimana BETWEEN 1 AND 7", self.sql)
        self.assertIn("giorno_successivo BOOLEAN", self.sql)
        self.assertIn("ora_inizio >= TIME '18:00'", self.sql)
        for state in STATI_RICHIESTA_DISPONIBILITA:
            self.assertIn(f"'{state}'", self.sql)

    def test_schema_ha_indici_operativi_e_antiduplicazione(self):
        self.assertIn("ux_richieste_disponibilita_pendente", self.sql)
        self.assertIn("WHERE stato = 'in_attesa'", self.sql)
        self.assertIn("idx_richieste_disponibilita_offerente", self.sql)
        self.assertIn("idx_richieste_disponibilita_richiedente", self.sql)
        self.assertIn("idx_richieste_disponibilita_annuncio", self.sql)

    def test_schema_concede_permessi_al_ruolo_applicativo(self):
        self.assertIn("localcare_app", self.sql)
        self.assertIn("GRANT SELECT, INSERT, UPDATE, DELETE", self.sql)
        self.assertIn("GRANT USAGE, SELECT", self.sql)

    def test_migrazione_non_letti_aggiunge_evento_e_non_ripete_backfill(self):
        migration = (
            ROOT
            / "migrations"
            / "20260925_richieste_disponibilita_non_lette.sql"
        ).read_text(encoding="utf-8")

        self.assertIn("evento_letto_at", migration)
        self.assertIn("information_schema.columns", migration)
        self.assertIn("ADD COLUMN", migration)
        self.assertIn("UPDATE richieste_disponibilita", migration)
        self.assertIn("created_at", migration)


if __name__ == "__main__":
    unittest.main()
