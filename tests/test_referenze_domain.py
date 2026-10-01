import unittest

from referenze import (
    REFERENCE_CONSENT_VERSION,
    decrypt_invitation_message,
    decrypt_reference_email,
    decrypt_reference_name,
    decrypt_reference_phone,
    encrypt_invitation_message,
    encrypt_reference_email,
    encrypt_reference_name,
    encrypt_reference_phone,
    generate_reference_token,
    hash_reference_token,
    normalize_reference_payload,
    normalize_reference_phone,
    reference_email_fingerprint,
    reference_token_matches,
    serialize_public_reference,
)


MASTER_SECRET = bytes(range(32))


class ReferenceCryptoTest(unittest.TestCase):
    def test_email_round_trip_e_fingerprint_normalizzato(self):
        encrypted = encrypt_reference_email(
            "  REFERENTE@Example.COM ",
            MASTER_SECRET,
        )
        self.assertEqual(
            decrypt_reference_email(
                encrypted["email_cifrata"],
                encrypted["email_nonce"],
                encrypted["email_tag"],
                MASTER_SECRET,
                key_id=encrypted["email_key_id"],
            ),
            "referente@example.com",
        )
        self.assertEqual(
            encrypted["email_hash"],
            reference_email_fingerprint(
                "referente@example.com",
                MASTER_SECRET,
            ),
        )
        self.assertNotIn("referente", encrypted["email_cifrata"])

    def test_nonce_casuale_e_tag_impediscono_manomissioni(self):
        first = encrypt_reference_email("ref@example.com", MASTER_SECRET)
        second = encrypt_reference_email("ref@example.com", MASTER_SECRET)
        self.assertNotEqual(first["email_cifrata"], second["email_cifrata"])
        self.assertNotEqual(first["email_nonce"], second["email_nonce"])
        with self.assertRaises(ValueError):
            decrypt_reference_email(
                first["email_cifrata"],
                first["email_nonce"],
                second["email_tag"],
                MASTER_SECRET,
            )

    def test_nome_e_messaggio_invito_restano_cifrati_e_separati(self):
        name = encrypt_reference_name("  Maria   Rossi ", MASTER_SECRET)
        message = encrypt_invitation_message(
            "Ho lavorato con te, puoi lasciare una referenza?",
            MASTER_SECRET,
        )
        self.assertEqual(
            decrypt_reference_name(
                name["nome_cifrato"],
                name["nome_nonce"],
                name["nome_tag"],
                MASTER_SECRET,
            ),
            "Maria Rossi",
        )
        self.assertIsNotNone(message)
        self.assertEqual(
            decrypt_invitation_message(
                message["messaggio_invito_cifrato"],
                message["messaggio_invito_nonce"],
                message["messaggio_invito_tag"],
                MASTER_SECRET,
            ),
            "Ho lavorato con te, puoi lasciare una referenza?",
        )
        self.assertIsNone(encrypt_invitation_message("  ", MASTER_SECRET))

    def test_telefono_round_trip_senza_valore_in_chiaro_o_hash(self):
        encrypted = encrypt_reference_phone(
            "  +39 333 123 4567 ",
            MASTER_SECRET,
        )
        self.assertEqual(
            set(encrypted),
            {"telefono_cifrato", "telefono_nonce", "telefono_tag"},
        )
        self.assertNotIn("333", encrypted["telefono_cifrato"])
        self.assertEqual(
            decrypt_reference_phone(
                encrypted["telefono_cifrato"],
                encrypted["telefono_nonce"],
                encrypted["telefono_tag"],
                MASTER_SECRET,
            ),
            "+39 333 123 4567",
        )

    def test_token_memorizzato_solo_come_hash(self):
        token = generate_reference_token()
        digest = hash_reference_token(token)
        self.assertGreaterEqual(len(token), 40)
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(token, digest)
        self.assertTrue(reference_token_matches(token, digest))
        self.assertFalse(reference_token_matches(token + "x", digest))

    def test_segreto_debole_rifiutato(self):
        with self.assertRaises(ValueError):
            encrypt_reference_email("ref@example.com", "troppo-corto")


class ReferenceValidationTest(unittest.TestCase):
    def test_normalizza_payload_completo(self):
        normalized = normalize_reference_payload(
            {
                "categoria_slug": " Babysitter ",
                "tipo_rapporto": "Famiglia",
                "anno_inizio": "2024",
                "anno_fine": 2025,
                "durata_fascia": "6_12_mesi",
                "esperienza_diretta": "on",
                "testo_referente": "Puntuale e affidabile.",
                "consenso_contatto": "1",
                "referente_telefono": "+39 333 123 4567",
                "autorizza_pubblicazione": True,
                "autorizza_testo_pubblico": True,
            },
            current_year=2026,
        )
        self.assertEqual(normalized["categoria_slug"], "babysitter")
        self.assertEqual(normalized["anno_inizio"], 2024)
        self.assertTrue(normalized["esperienza_diretta"])
        self.assertTrue(normalized["autorizza_contatto_verifica"])
        self.assertEqual(
            normalized["referente_telefono"],
            "+39 333 123 4567",
        )
        self.assertTrue(normalized["autorizza_testo_pubblico"])
        self.assertEqual(REFERENCE_CONSENT_VERSION, "references_2026_v3")

    def test_telefono_e_validato_e_richiede_consenso_abbinato(self):
        base = {
            "categoria_slug": "babysitter",
            "tipo_rapporto": "famiglia",
            "durata_fascia": "6_12_mesi",
            "esperienza_diretta": "1",
        }
        self.assertIsNone(normalize_reference_phone("  "))
        for invalid in (
            "333-ABC-1234",
            "+39 +333 1234567",
            "12345",
            "+1234567890123456",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_reference_phone(invalid)

        for mismatched in (
            {"referente_telefono": "+39 333 123 4567"},
            {"autorizza_contatto_verifica": "on"},
        ):
            with self.subTest(mismatched=mismatched), self.assertRaisesRegex(
                ValueError,
                "devono essere indicati insieme",
            ):
                normalize_reference_payload({**base, **mismatched})

        normalized = normalize_reference_payload(base)
        self.assertFalse(normalized["autorizza_contatto_verifica"])
        self.assertIsNone(normalized["referente_telefono"])

        declined = normalize_reference_payload({
            **base,
            "esperienza_diretta": "0",
            "autorizza_contatto_verifica": "on",
            "referente_telefono": "+39 333 123 4567",
        })
        self.assertFalse(declined["autorizza_contatto_verifica"])
        self.assertIsNone(declined["referente_telefono"])

    def test_durata_strutturata_e_limite_messaggio_sono_server_side(self):
        with self.assertRaises(ValueError):
            normalize_reference_payload({
                "categoria_slug": "babysitter",
                "tipo_rapporto": "famiglia",
            })
        with self.assertRaises(ValueError):
            encrypt_invitation_message("x" * 501, MASTER_SECRET)

    def test_rifiuta_periodo_e_recapiti_nel_testo_pubblico(self):
        base = {
            "categoria_slug": "babysitter",
            "tipo_rapporto": "famiglia",
        }
        with self.assertRaises(ValueError):
            normalize_reference_payload(
                {**base, "anno_inizio": 2025, "anno_fine": 2024},
                current_year=2026,
            )
        with self.assertRaises(ValueError):
            normalize_reference_payload(
                {**base, "testo_referente": "Scrivimi a ref@example.com"},
                current_year=2026,
            )
        with self.assertRaises(ValueError):
            normalize_reference_payload(
                {
                    **base,
                    "testo_referente": "Profilo instagram.com/referente",
                },
                current_year=2026,
            )
        with self.assertRaises(ValueError):
            normalize_reference_payload(
                {**base, "testo_referente": "Contattami come @referente"},
                current_year=2026,
            )

    def test_il_testo_puo_contenere_nomi_propri(self):
        normalized = normalize_reference_payload(
            {
                "categoria_slug": "babysitter",
                "tipo_rapporto": "famiglia",
                "durata_fascia": "6_12_mesi",
                "testo_referente": (
                    "Maria Rossi ha seguito nostra figlia con attenzione."
                ),
                "autorizza_pubblicazione": True,
                "autorizza_testo_pubblico": True,
            },
            current_year=2026,
        )
        self.assertIn("Maria Rossi", normalized["testo_referente"])

    def test_consenso_scheda_governa_anche_il_testo_facoltativo(self):
        base = {
            "categoria_slug": "caregiver",
            "tipo_rapporto": "datore_lavoro",
            "durata_fascia": "6_12_mesi",
            "esperienza_diretta": True,
            "testo_referente": "Rapporto confermato.",
        }
        private = normalize_reference_payload(
            {**base, "autorizza_testo_pubblico": True},
            current_year=2026,
        )
        public = normalize_reference_payload(
            {**base, "autorizza_pubblicazione": True},
            current_year=2026,
        )
        empty = normalize_reference_payload(
            {
                **base,
                "testo_referente": "",
                "autorizza_pubblicazione": True,
            },
            current_year=2026,
        )

        self.assertFalse(private["autorizza_testo_pubblico"])
        self.assertTrue(public["autorizza_testo_pubblico"])
        self.assertFalse(empty["autorizza_testo_pubblico"])

    def test_serializzazione_pubblica_e_allowlist(self):
        row = {
            "id": 8,
            "utente_id": 99,
            "categoria_slug": "caregiver",
            "tipo_rapporto": "datore_lavoro",
            "anno_inizio": 2023,
            "anno_fine": 2025,
            "durata_fascia": "oltre_2_anni",
            "esperienza_diretta": 1,
            "testo_referente": "Collaborazione positiva.",
            "stato_risposta": "risposta_ricevuta",
            "stato_verifica": "verificata",
            "autorizza_pubblicazione": 1,
            "autorizza_testo_pubblico": 1,
            "pubblicazione_approvata_admin": 1,
            "visibile_profilo": 1,
            "risposta_at": "2026-09-28T10:00:00Z",
            "verificata_at": "2026-09-28T12:00:00Z",
            "nota_pubblica": "Rapporto confermato dal referente.",
            "nota_admin": "Non deve uscire.",
            "email_cifrata": "Non deve uscire.",
            "telefono_cifrato": "Non deve uscire.",
            "revocata_at": None,
            "cancellata_at": None,
        }
        public = serialize_public_reference(row)
        self.assertTrue(public["verificata_da_mylocalcare"])
        self.assertEqual(public["testo_referente"], "Collaborazione positiva.")
        self.assertNotIn("periodo", public)
        self.assertNotIn("nota_pubblica", public)
        self.assertNotIn("utente_id", public)
        self.assertNotIn("nota_admin", public)
        self.assertNotIn("telefono_cifrato", public)
        self.assertNotIn("email_cifrata", public)

        row["autorizza_testo_pubblico"] = 0
        self.assertIsNone(serialize_public_reference(row)["testo_referente"])
        row["autorizza_pubblicazione"] = 0
        self.assertIsNone(serialize_public_reference(row))

    def test_referenza_smentita_non_resta_pubblica(self):
        row = {
            "id": 11,
            "categoria_slug": "babysitter",
            "tipo_rapporto": "famiglia",
            "esperienza_diretta": 1,
            "stato_risposta": "risposta_ricevuta",
            "stato_verifica": "non_confermata",
            "autorizza_pubblicazione": 1,
            "pubblicazione_approvata_admin": 1,
            "visibile_profilo": 1,
            "revocata_at": None,
            "cancellata_at": None,
        }
        self.assertIsNone(serialize_public_reference(row))

    def test_esito_non_verificabile_resta_una_referenza_ricevuta(self):
        row = {
            "id": 12,
            "categoria_slug": "caregiver",
            "tipo_rapporto": "cliente",
            "esperienza_diretta": 1,
            "stato_risposta": "risposta_ricevuta",
            "stato_verifica": "non_verificabile",
            "autorizza_pubblicazione": 1,
            "pubblicazione_approvata_admin": 1,
            "visibile_profilo": 1,
            "revocata_at": None,
            "cancellata_at": None,
        }
        public = serialize_public_reference(row)
        self.assertIsNotNone(public)
        self.assertEqual(public["stato_verifica"], "non_esaminata")
        self.assertEqual(public["stato_verifica_label"], "Referenza ricevuta")
        self.assertFalse(public["verificata_da_mylocalcare"])

    def test_coda_admin_non_viene_presentata_come_controllo_in_corso(self):
        row = {
            "id": 13,
            "categoria_slug": "babysitter",
            "tipo_rapporto": "famiglia",
            "esperienza_diretta": 1,
            "stato_risposta": "risposta_ricevuta",
            "stato_verifica": "in_coda",
            "autorizza_pubblicazione": 1,
            "pubblicazione_approvata_admin": 1,
            "visibile_profilo": 1,
            "revocata_at": None,
            "cancellata_at": None,
        }
        public = serialize_public_reference(row)
        self.assertEqual(public["stato_verifica_label"], "Referenza ricevuta")

    def test_serve_approvazione_admin_e_scelta_visibilita_proprietario(self):
        row = {
            "id": 14,
            "categoria_slug": "babysitter",
            "tipo_rapporto": "famiglia",
            "esperienza_diretta": 1,
            "stato_risposta": "risposta_ricevuta",
            "stato_verifica": "verificata",
            "autorizza_pubblicazione": 1,
            "pubblicazione_approvata_admin": 0,
            "visibile_profilo": 1,
            "revocata_at": None,
            "cancellata_at": None,
        }
        self.assertIsNone(serialize_public_reference(row))

        row["pubblicazione_approvata_admin"] = 1
        row["visibile_profilo"] = 0
        self.assertIsNone(serialize_public_reference(row))

        row["visibile_profilo"] = 1
        self.assertIsNotNone(serialize_public_reference(row))


if __name__ == "__main__":
    unittest.main()
