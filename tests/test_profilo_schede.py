import importlib.util
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from profilo_schede import (
    CATALOGO_SCHEDE_SEED,
    PROFILE_CARD_CATEGORIES,
    card_content_changed,
    card_public_details,
    effective_verification_state,
    group_cards_by_legacy_key,
    normalize_card_payload,
    public_verification_label,
    verification_reset_patch,
)


ROOT = Path(__file__).resolve().parents[1]


def load_init_db_without_flask():
    """Carica le sole routine DB senza importare l'applicazione Flask."""

    fake_app_module = types.ModuleType("app")
    fake_app_module.app = object()
    fake_app_module.sql = lambda query: query
    fake_app_module.now_sql = lambda: "CURRENT_TIMESTAMP"

    module_name = "init_db_schede_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "init_db.py",
    )
    module = importlib.util.module_from_spec(spec)
    original_directory = Path.cwd()
    with tempfile.TemporaryDirectory() as isolated_directory:
        try:
            os.chdir(isolated_directory)
            with mock.patch.dict(
                sys.modules,
                {"app": fake_app_module, module_name: module},
            ), mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DATABASE_URL", None)
                spec.loader.exec_module(module)
        finally:
            os.chdir(original_directory)
    return module


class ProfiloSchedeValidationTest(unittest.TestCase):
    def test_catalogo_copre_tutte_le_categorie_ed_ha_codici_unici(self):
        codes = [entry["codice"] for entry in CATALOGO_SCHEDE_SEED]
        covered = {
            category
            for entry in CATALOGO_SCHEDE_SEED
            for category in entry["categorie"]
        }

        self.assertEqual(len(codes), len(set(codes)))
        self.assertEqual(covered, PROFILE_CARD_CATEGORIES)

    def test_migrazione_produzione_contiene_tutto_il_seed(self):
        migration = (
            ROOT / "migrations" / "20260924_schede_profilo.sql"
        ).read_text(encoding="utf-8")

        self.assertNotIn("\n+", migration)
        self.assertNotIn("__CATALOGO_SEED__", migration)
        for entry in CATALOGO_SCHEDE_SEED:
            escaped_code = entry["codice"].replace("'", "''")
            self.assertIn(f"'{escaped_code}'", migration)
        self.assertIn("versione INTEGER NOT NULL DEFAULT 1", migration)
        self.assertIn("ON DELETE CASCADE", migration)

    def test_payload_catalogo_impone_tipo_categoria_ed_ente(self):
        entry = {
            "id": 7,
            "titolo": "Attestato BLSD",
            "tipo_scheda": "certificazione",
            "categorie": ("babysitter", "caregiver"),
            "richiede_ente": True,
            "attivo": True,
        }
        payload = {
            "legacy_key": "certificazioni",
            "catalogo_id": 7,
            "categoria_slug": "babysitter",
            "ente": "Croce esempio",
            "in_corso": "false",
            "data_rilascio": "2026-01-10",
            "data_scadenza": "2028-01-10",
        }

        normalized = normalize_card_payload(payload, catalog_entry=entry)

        self.assertEqual(normalized["titolo"], "Attestato BLSD")
        self.assertFalse(normalized["in_corso"])
        self.assertEqual(normalized["ente"], "Croce esempio")

        without_issuer = dict(payload, ente="")
        with self.assertRaisesRegex(ValueError, "Ente è obbligatorio"):
            normalize_card_payload(without_issuer, catalog_entry=entry)

        wrong_category = dict(payload, categoria_slug="pet-sitter")
        with self.assertRaisesRegex(ValueError, "categoria"):
            normalize_card_payload(wrong_category, catalog_entry=entry)

    def test_payload_libero_rifiuta_slot_tipo_e_date_incoerenti(self):
        with self.assertRaisesRegex(ValueError, "Tipo di scheda"):
            normalize_card_payload({
                "legacy_key": "esperienza_1",
                "tipo_scheda": "formazione",
                "titolo": "Esperienza",
            })

    def test_payload_pubblico_rifiuta_recapiti_diretti(self):
        base = {
            "legacy_key": "esperienza_1",
            "titolo": "Babysitter",
        }
        for field, value in (
            ("titolo", "Babysitter 333 123 4567"),
            ("ente", "Scrivimi a nome@example.com"),
            ("luogo", "Contattami su WhatsApp"),
            ("descrizione", "Portfolio: https://example.com/profilo"),
            ("descrizione", "Instagram: @mario.rossi"),
            ("descrizione", "Profilo su facebook.com/mario"),
            ("descrizione", "IG mario_rossi"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non può contenere"):
                    normalize_card_payload(dict(base, **{field: value}))

        with self.assertRaisesRegex(ValueError, "fine precede"):
            normalize_card_payload({
                "legacy_key": "esperienza_1",
                "titolo": "Babysitter",
                "data_inizio": "2026-02-01",
                "data_fine": "2026-01-01",
            })

    def test_modifica_resetta_richiesta_o_verifica_ma_non_un_salvataggio_identico(self):
        previous = {
            "legacy_key": "esperienza_1",
            "tipo_scheda": "esperienza",
            "catalogo_id": None,
            "titolo": "Babysitter",
            "categoria_slug": "babysitter",
            "ente": "",
            "luogo": "Milano",
            "data_inizio": "2025-01-01",
            "data_fine": None,
            "in_corso": 1,
            "data_rilascio": None,
            "data_scadenza": None,
            "codice_qualifica": "",
            "descrizione": "Due famiglie",
            "stato_verifica": "documento_visionato",
        }
        identical = {key: previous.get(key) for key in previous}
        identical.pop("stato_verifica")

        self.assertFalse(card_content_changed(previous, identical))
        self.assertEqual(verification_reset_patch(previous, identical), {})

        changed = dict(identical, descrizione="Tre famiglie")
        reset = verification_reset_patch(previous, changed)

        self.assertEqual(reset["stato_verifica"], "dichiarata")
        self.assertEqual(reset["metodo_verifica"], "nessuno")
        self.assertIsNone(reset["verificata_at"])
        self.assertIsNone(reset["nota_pubblica"])

    def test_popup_pubblico_espone_solo_le_due_formule_positive(self):
        card = {
            "id": 12,
            "legacy_key": "studio_1",
            "tipo_scheda": "formazione",
            "titolo": "Laurea",
            "codice_qualifica": "3331234567",
            "stato_verifica": "non_confermata",
            "verificata_at": "2026-09-24T10:00:00+00:00",
            "nota_pubblica": "Nota non più applicabile",
        }
        public = card_public_details(card)

        self.assertEqual(public["stato_verifica"], "dichiarata")
        self.assertEqual(
            public["etichetta_verifica"],
            "Dichiarato dall'utente",
        )
        self.assertEqual(public["verificata_at"], "")

        verified_with_code = card_public_details({
            **card,
            "stato_verifica": "documento_visionato",
            "codice_qualifica": "3331234567",
        })
        self.assertEqual(verified_with_code["codice_qualifica"], "")
        self.assertNotIn("nota_pubblica", public)
        self.assertEqual(public["codice_qualifica"], "")
        self.assertEqual(
            public_verification_label("documento_visionato"),
            "Documento visionato da MyLocalCare",
        )
        self.assertEqual(
            public_verification_label("riscontro_effettuato"),
            "Riscontro effettuato da MyLocalCare",
        )

    def test_richiesta_e_mancata_conferma_restano_visibili_come_dichiarate(self):
        cards = []
        for card_id, state in ((31, "richiesta"), (32, "non_confermata")):
            public = card_public_details({
                "id": card_id,
                "legacy_key": "esperienza_1",
                "tipo_scheda": "esperienza",
                "titolo": "Babysitter",
                "descrizione": "Esperienza con due famiglie",
                "stato_verifica": state,
                "verificata_at": "2026-09-24T10:00:00+00:00",
            })
            self.assertEqual(public["id"], card_id)
            self.assertEqual(public["titolo"], "Babysitter")
            self.assertEqual(public["descrizione"], "Esperienza con due famiglie")
            self.assertEqual(public["stato_verifica"], "dichiarata")
            self.assertEqual(public["etichetta_verifica"], "Dichiarato dall'utente")
            self.assertEqual(public["verificata_at"], "")
            cards.append(public)

        grouped = group_cards_by_legacy_key(cards)
        self.assertEqual([card["id"] for card in grouped["esperienza_1"]], [31, 32])

    def test_controllo_positivo_scaduto_non_resta_pubblicamente_verificato(self):
        card = {
            "id": 13,
            "legacy_key": "certificazioni",
            "tipo_scheda": "certificazione",
            "titolo": "BLSD",
            "stato_verifica": "documento_visionato",
            "data_scadenza": "2026-09-23",
            "verificata_at": "2026-01-10T10:00:00+00:00",
        }

        self.assertEqual(
            effective_verification_state(card, today=date(2026, 9, 24)),
            "scaduta",
        )
        public = card_public_details(card)
        self.assertEqual(public["stato_verifica"], "dichiarata")
        self.assertEqual(public["etichetta_verifica"], "Dichiarato dall'utente")
        self.assertEqual(public["verificata_at"], "")


class ProfiloSchedeSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.init_db = load_init_db_without_flask()

    def setUp(self):
        temp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        temp.close()
        self.database_path = Path(temp.name)

        conn = self._connect()
        conn.execute("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                ruolo TEXT DEFAULT 'user'
            )
        """)
        conn.executemany(
            "INSERT INTO utenti (id, ruolo) VALUES (?, ?)",
            [(1, "user"), (2, "admin")],
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.database_path.unlink(missing_ok=True)

    def _connect(self):
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def test_bootstrap_e_seed_sono_idempotenti_e_non_sovrascrivono_admin(self):
        with mock.patch.object(
            self.init_db,
            "get_conn",
            side_effect=self._connect,
        ):
            self.init_db.crea_tabelle_schede_profilo()
            self.init_db.crea_tabelle_schede_profilo()
            self.init_db.semina_catalogo_qualifiche()
            self.init_db.semina_catalogo_qualifiche()

            conn = self._connect()
            total = conn.execute(
                "SELECT COUNT(*) FROM catalogo_qualifiche"
            ).fetchone()[0]
            links = conn.execute(
                "SELECT COUNT(*) FROM catalogo_qualifiche_categorie"
            ).fetchone()[0]
            expected_links = sum(
                len(entry["categorie"])
                for entry in CATALOGO_SCHEDE_SEED
            )
            self.assertEqual(total, len(CATALOGO_SCHEDE_SEED))
            self.assertEqual(links, expected_links)

            conn.execute("""
                UPDATE catalogo_qualifiche
                SET titolo = 'Titolo admin', attivo = 0
                WHERE codice = 'exp_babysitter'
            """)
            conn.commit()
            conn.close()

            self.init_db.semina_catalogo_qualifiche()
            conn = self._connect()
            row = conn.execute("""
                SELECT titolo, attivo
                FROM catalogo_qualifiche
                WHERE codice = 'exp_babysitter'
            """).fetchone()
            conn.close()

        self.assertEqual(row["titolo"], "Titolo admin")
        self.assertEqual(row["attivo"], 0)

    def test_un_solo_slot_attivo_ma_certificazioni_multiple(self):
        with mock.patch.object(
            self.init_db,
            "get_conn",
            side_effect=self._connect,
        ):
            self.init_db.crea_tabelle_schede_profilo()

        conn = self._connect()
        conn.execute("""
            INSERT INTO schede_profilo (
                utente_id, legacy_key, tipo_scheda, titolo
            ) VALUES (1, 'esperienza_1', 'esperienza', 'Prima')
        """)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("""
                INSERT INTO schede_profilo (
                    utente_id, legacy_key, tipo_scheda, titolo
                ) VALUES (1, 'esperienza_1', 'esperienza', 'Seconda')
            """)
        conn.rollback()

        conn.executemany("""
            INSERT INTO schede_profilo (
                utente_id, legacy_key, tipo_scheda, titolo
            ) VALUES (1, 'certificazioni', 'certificazione', ?)
        """, [("BLSD",), ("Primo soccorso",)])
        total = conn.execute("""
            SELECT COUNT(*) FROM schede_profilo
            WHERE legacy_key = 'certificazioni' AND attiva = 1
        """).fetchone()[0]
        conn.close()

        self.assertEqual(total, 2)

    def test_database_rifiuta_tipo_non_coerente_con_slot(self):
        with mock.patch.object(
            self.init_db,
            "get_conn",
            side_effect=self._connect,
        ):
            self.init_db.crea_tabelle_schede_profilo()

        conn = self._connect()
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("""
                INSERT INTO schede_profilo (
                    utente_id, legacy_key, tipo_scheda, titolo
                ) VALUES (1, 'studio_1', 'esperienza', 'Non coerente')
            """)
        conn.close()

    def test_storico_prevede_snapshot_dei_dati_controllati(self):
        with mock.patch.object(
            self.init_db,
            "get_conn",
            side_effect=self._connect,
        ):
            self.init_db.crea_tabelle_schede_profilo()

        conn = self._connect()
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(schede_profilo_verifiche)"
            ).fetchall()
        }
        conn.close()

        self.assertIn("scheda_snapshot", columns)

    def test_scheda_prevede_versione_intera_per_concorrenza(self):
        with mock.patch.object(
            self.init_db,
            "get_conn",
            side_effect=self._connect,
        ):
            self.init_db.crea_tabelle_schede_profilo()

        conn = self._connect()
        columns = {
            row["name"]: row
            for row in conn.execute(
                "PRAGMA table_info(schede_profilo)"
            ).fetchall()
        }
        conn.close()

        self.assertIn("versione", columns)
        self.assertEqual(columns["versione"]["notnull"], 1)
        self.assertEqual(str(columns["versione"]["dflt_value"]), "1")


if __name__ == "__main__":
    unittest.main()
