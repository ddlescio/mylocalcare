import copy
import unittest
from datetime import date, datetime, timedelta, timezone

from disponibilita_servizi import (
    CODICE_ESCLUSA_FILTRO,
    CODICE_FRESCA,
    CODICE_MAI_CONFERMATA,
    CODICE_PRIORITA_RIDOTTA,
    CODICE_RICONFERMA,
    FASCE_DISPONIBILITA,
    GIORNI_ESCLUSIONE_FILTRO,
    GIORNI_PRIORITA_RIDOTTA,
    GIORNI_RICONFERMA,
    MAX_ASSENZE,
    MAX_DATE_SPECIALI,
    MAX_RIGHE_SETTIMANALI,
    STATI_DISPONIBILITA,
    calcola_freschezza_disponibilita,
    normalize_disponibilita_payload,
    serializza_disponibilita_pubblica,
)


def valid_payload(**overrides):
    payload = {
        "stato": "disponibile",
        "settimanale": [],
        "date_speciali": [],
        "assenze": [],
    }
    payload.update(overrides)
    return payload


class DisponibilitaNormalizationTest(unittest.TestCase):
    def test_vocabolari_pubblici_sono_chiusi_e_stabili(self):
        self.assertEqual(
            STATI_DISPONIBILITA,
            ("disponibile", "limitata", "non_disponibile"),
        )
        self.assertEqual(
            FASCE_DISPONIBILITA,
            ("mattina", "pomeriggio", "sera", "notte"),
        )

    def test_normalizza_ordina_e_rimuove_duplicati(self):
        payload = valid_payload(
            stato=" LIMITATA ",
            settimanale=[
                {"giorno_settimana": 2, "fascia": "sera"},
                {"giorno_settimana": 1, "fascia": "pomeriggio"},
                {"giorno_settimana": 1, "fascia": "mattina"},
                {"giorno_settimana": 2, "fascia": "sera"},
            ],
            date_speciali=[
                {
                    "data": "2026-11-03",
                    "tipo": "disponibile",
                    "fasce": ["sera", "mattina", "sera"],
                },
                {
                    "data": "2026-11-03",
                    "tipo": "disponibile",
                    "fasce": ["pomeriggio"],
                },
                {
                    "data": "2026-11-02",
                    "tipo": "non_disponibile",
                    "fasce": [],
                },
            ],
            assenze=[
                {"data_inizio": "2026-12-05", "data_fine": "2026-12-08"},
                {"data_inizio": "2026-12-01", "data_fine": "2026-12-05"},
                {"data_inizio": "2026-12-09", "data_fine": "2026-12-10"},
                {"data_inizio": "2026-12-01", "data_fine": "2026-12-05"},
            ],
        )
        original = copy.deepcopy(payload)

        normalized = normalize_disponibilita_payload(payload)

        self.assertEqual(payload, original)
        self.assertEqual(normalized["stato"], "limitata")
        self.assertEqual(normalized["settimanale"], [
            {"giorno_settimana": 1, "fascia": "mattina"},
            {"giorno_settimana": 1, "fascia": "pomeriggio"},
            {"giorno_settimana": 2, "fascia": "sera"},
        ])
        self.assertEqual(normalized["date_speciali"], [
            {
                "data": "2026-11-02",
                "tipo": "non_disponibile",
                "fasce": [],
            },
            {
                "data": "2026-11-03",
                "tipo": "disponibile",
                "fasce": ["mattina", "pomeriggio", "sera"],
            },
        ])
        self.assertEqual(normalized["assenze"], [
            {"data_inizio": "2026-12-01", "data_fine": "2026-12-10"},
        ])

    def test_collezioni_omesse_diventano_liste_vuote(self):
        self.assertEqual(
            normalize_disponibilita_payload({"stato": "non_disponibile"}),
            {
                "stato": "non_disponibile",
                "settimanale": [],
                "date_speciali": [],
                "assenze": [],
            },
        )

    def test_rifiuta_stato_giorno_e_fascia_non_validi(self):
        invalid_payloads = (
            valid_payload(stato="forse"),
            valid_payload(settimanale=[
                {"giorno_settimana": 0, "fascia": "mattina"},
            ]),
            valid_payload(settimanale=[
                {"giorno_settimana": 8, "fascia": "mattina"},
            ]),
            valid_payload(settimanale=[
                {"giorno_settimana": True, "fascia": "mattina"},
            ]),
            valid_payload(settimanale=[
                {"giorno_settimana": 1, "fascia": "pranzo"},
            ]),
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    normalize_disponibilita_payload(payload)

    def test_rifiuta_testo_libero_recapiti_e_campi_sconosciuti(self):
        for key, value in (
            ("note", "Chiamami al 3331234567"),
            ("telefono", "+39 3331234567"),
            ("email", "utente@example.com"),
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "non consentiti"):
                    normalize_disponibilita_payload(
                        valid_payload(**{key: value})
                    )

        with self.assertRaisesRegex(ValueError, "non consentiti"):
            normalize_disponibilita_payload(valid_payload(settimanale=[{
                "giorno_settimana": 1,
                "fascia": "mattina",
                "nota": "WhatsApp 3331234567",
            }]))

    def test_rifiuta_formati_e_tipi_non_previsti(self):
        with self.assertRaisesRegex(ValueError, "deve essere una lista"):
            normalize_disponibilita_payload(valid_payload(settimanale="lunedi"))
        with self.assertRaisesRegex(ValueError, "deve essere un oggetto"):
            normalize_disponibilita_payload([])
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            normalize_disponibilita_payload(valid_payload(date_speciali=[{
                "data": "03/11/2026",
                "tipo": "non_disponibile",
                "fasce": [],
            }]))
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            normalize_disponibilita_payload(valid_payload(assenze=[{
                "data_inizio": "2026-1-02",
                "data_fine": "2026-01-03",
            }]))

    def test_data_chiusa_non_ha_fasce_e_data_aperta_ne_richiede_una(self):
        with self.assertRaisesRegex(ValueError, "deve essere vuoto"):
            normalize_disponibilita_payload(valid_payload(date_speciali=[{
                "data": "2026-11-03",
                "tipo": "non_disponibile",
                "fasce": ["mattina"],
            }]))
        with self.assertRaisesRegex(ValueError, "almeno una fascia"):
            normalize_disponibilita_payload(valid_payload(date_speciali=[{
                "data": "2026-11-03",
                "tipo": "disponibile",
                "fasce": [],
            }]))

    def test_rifiuta_date_speciali_duplicate_in_conflitto(self):
        with self.assertRaisesRegex(ValueError, "in conflitto"):
            normalize_disponibilita_payload(valid_payload(date_speciali=[
                {
                    "data": "2026-11-03",
                    "tipo": "disponibile",
                    "fasce": ["mattina"],
                },
                {
                    "data": "2026-11-03",
                    "tipo": "non_disponibile",
                    "fasce": [],
                },
            ]))

    def test_rifiuta_disponibilita_speciale_durante_assenza(self):
        with self.assertRaisesRegex(ValueError, "periodo di assenza"):
            normalize_disponibilita_payload(valid_payload(
                date_speciali=[{
                    "data": "2026-11-03",
                    "tipo": "disponibile",
                    "fasce": ["mattina"],
                }],
                assenze=[{
                    "data_inizio": "2026-11-01",
                    "data_fine": "2026-11-05",
                }],
            ))

    def test_data_chiusa_puo_coincidere_con_assenza(self):
        normalized = normalize_disponibilita_payload(valid_payload(
            date_speciali=[{
                "data": "2026-11-03",
                "tipo": "non_disponibile",
                "fasce": [],
            }],
            assenze=[{
                "data_inizio": "2026-11-01",
                "data_fine": "2026-11-05",
            }],
        ))
        self.assertEqual(normalized["date_speciali"][0]["tipo"], "non_disponibile")

    def test_rifiuta_assenza_con_intervallo_invertito(self):
        with self.assertRaisesRegex(ValueError, "precede"):
            normalize_disponibilita_payload(valid_payload(assenze=[{
                "data_inizio": "2026-11-05",
                "data_fine": "2026-11-01",
            }]))

    def test_applica_limite_alle_date_speciali(self):
        start = date(2026, 1, 1)
        rows = [
            {
                "data": (start + timedelta(days=index)).isoformat(),
                "tipo": "non_disponibile",
                "fasce": [],
            }
            for index in range(MAX_DATE_SPECIALI + 1)
        ]
        with self.assertRaisesRegex(ValueError, str(MAX_DATE_SPECIALI)):
            normalize_disponibilita_payload(valid_payload(date_speciali=rows))

    def test_applica_limite_alle_righe_settimanali(self):
        rows = [
            {"giorno_settimana": 1, "fascia": "mattina"}
            for _ in range(MAX_RIGHE_SETTIMANALI + 1)
        ]
        with self.assertRaisesRegex(ValueError, str(MAX_RIGHE_SETTIMANALI)):
            normalize_disponibilita_payload(valid_payload(settimanale=rows))

    def test_applica_limite_ai_periodi_di_assenza_normalizzati(self):
        start = date(2026, 1, 1)
        rows = [
            {
                "data_inizio": (start + timedelta(days=index * 2)).isoformat(),
                "data_fine": (start + timedelta(days=index * 2)).isoformat(),
            }
            for index in range(MAX_ASSENZE + 1)
        ]
        with self.assertRaisesRegex(ValueError, str(MAX_ASSENZE)):
            normalize_disponibilita_payload(valid_payload(assenze=rows))


class DisponibilitaFreshnessTest(unittest.TestCase):
    def setUp(self):
        self.confirmed = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def freshness_at(self, days=0, seconds=0):
        return calcola_freschezza_disponibilita(
            self.confirmed,
            now=self.confirmed + timedelta(days=days, seconds=seconds),
        )

    def test_soglie_sono_quelle_di_prodotto(self):
        self.assertEqual(GIORNI_RICONFERMA, 30)
        self.assertEqual(GIORNI_PRIORITA_RIDOTTA, 37)
        self.assertEqual(GIORNI_ESCLUSIONE_FILTRO, 44)

    def test_prima_dei_30_giorni_e_aggiornata(self):
        result = self.freshness_at(days=30, seconds=-1)
        self.assertEqual(result["codice"], CODICE_FRESCA)
        self.assertFalse(result["riconferma_richiesta"])
        self.assertFalse(result["priorita_ridotta"])
        self.assertTrue(result["inclusa_filtro_disponibili"])

    def test_a_30_giorni_richiede_riconferma(self):
        result = self.freshness_at(days=30)
        self.assertEqual(result["codice"], CODICE_RICONFERMA)
        self.assertTrue(result["riconferma_richiesta"])
        self.assertFalse(result["priorita_ridotta"])
        self.assertTrue(result["inclusa_filtro_disponibili"])

    def test_a_37_giorni_riduce_priorita(self):
        just_before = self.freshness_at(days=37, seconds=-1)
        at_boundary = self.freshness_at(days=37)
        self.assertEqual(just_before["codice"], CODICE_RICONFERMA)
        self.assertEqual(at_boundary["codice"], CODICE_PRIORITA_RIDOTTA)
        self.assertTrue(at_boundary["priorita_ridotta"])
        self.assertTrue(at_boundary["inclusa_filtro_disponibili"])

    def test_a_44_giorni_esclude_dal_filtro(self):
        just_before = self.freshness_at(days=44, seconds=-1)
        at_boundary = self.freshness_at(days=44)
        self.assertEqual(just_before["codice"], CODICE_PRIORITA_RIDOTTA)
        self.assertEqual(at_boundary["codice"], CODICE_ESCLUSA_FILTRO)
        self.assertFalse(at_boundary["inclusa_filtro_disponibili"])

    def test_restituisce_metadati_dei_confini(self):
        result = self.freshness_at(days=10)
        self.assertEqual(result["giorni_trascorsi"], 10)
        self.assertEqual(result["confini_giorni"], {
            "riconferma": 30,
            "priorita_ridotta": 37,
            "esclusione_filtro": 44,
        })
        self.assertEqual(
            result["confini_at"]["riconferma"],
            "2026-01-31T12:00:00Z",
        )
        self.assertEqual(
            result["confini_at"]["priorita_ridotta"],
            "2026-02-07T12:00:00Z",
        )
        self.assertEqual(
            result["confini_at"]["esclusione_filtro"],
            "2026-02-14T12:00:00Z",
        )

    def test_mai_confermata_e_esclusa(self):
        result = calcola_freschezza_disponibilita(None, now=self.confirmed)
        self.assertEqual(result["codice"], CODICE_MAI_CONFERMATA)
        self.assertTrue(result["riconferma_richiesta"])
        self.assertTrue(result["priorita_ridotta"])
        self.assertFalse(result["inclusa_filtro_disponibili"])
        self.assertIsNone(result["confini_at"]["riconferma"])

    def test_accetta_stringa_z_naive_e_date(self):
        result_z = calcola_freschezza_disponibilita(
            "2026-01-01T12:00:00Z",
            now="2026-01-31T12:00:00+00:00",
        )
        result_naive = calcola_freschezza_disponibilita(
            datetime(2026, 1, 1, 12, 0),
            now=datetime(2026, 1, 31, 12, 0),
        )
        result_date = calcola_freschezza_disponibilita(
            date(2026, 1, 1),
            now=date(2026, 1, 31),
        )
        self.assertEqual(result_z["codice"], CODICE_RICONFERMA)
        self.assertEqual(result_naive["codice"], CODICE_RICONFERMA)
        self.assertEqual(result_date["codice"], CODICE_RICONFERMA)


class DisponibilitaPublicSerializerTest(unittest.TestCase):
    def test_whitelist_pubblica_esclude_campi_tecnici_e_precisione_oraria(self):
        source = valid_payload(
            stato="limitata",
            settimanale=[{"giorno_settimana": 1, "fascia": "mattina"}],
        )
        source.update({
            "utente_id": 99,
            "email": "privata@example.com",
            "ultimo_promemoria_at": "2026-01-20T10:30:00Z",
            "versione": 8,
        })
        result = serializza_disponibilita_pubblica(
            source,
            confermata_at="2026-01-01T12:34:56Z",
            now="2026-01-02T12:34:56Z",
        )

        self.assertEqual(set(result), {
            "stato",
            "settimanale",
            "date_speciali",
            "assenze",
            "freschezza",
        })
        self.assertNotIn("utente_id", result)
        self.assertNotIn("email", result)
        self.assertEqual(result["freschezza"]["confermata_il"], "2026-01-01")
        self.assertNotIn("confermata_at", result["freschezza"])

    def test_serializzatore_rivalida_i_dati_pubblici(self):
        with self.assertRaises(ValueError):
            serializza_disponibilita_pubblica(
                valid_payload(settimanale=[{
                    "giorno_settimana": 9,
                    "fascia": "mattina",
                }]),
                confermata_at="2026-01-01T00:00:00Z",
            )


if __name__ == "__main__":
    unittest.main()
