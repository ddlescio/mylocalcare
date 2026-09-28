from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "admin_referenze.html"
APP = ROOT / "app.py"


class AdminReferenzeTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = TEMPLATE.read_text(encoding="utf-8")
        cls.app = APP.read_text(encoding="utf-8")

    def test_mobile_first_cards_and_summary_counters_are_present(self):
        self.assertIn("Referenze utenti", self.body)
        self.assertIn("conteggi.get('da_gestire'", self.body)
        self.assertIn("conteggi.get('verificate'", self.body)
        self.assertIn("conteggi.get('totale'", self.body)
        self.assertIn("grid gap-4 lg:grid-cols-2", self.body)

    def test_filters_use_expected_context(self):
        self.assertIn('name="q"', self.body)
        self.assertIn('name="stato"', self.body)
        self.assertIn('name="categoria"', self.body)
        self.assertIn("categorie_referenze", self.body)
        self.assertIn("url_for('admin_referenze')", self.body)

    def test_private_referee_data_are_clearly_admin_only(self):
        self.assertIn("Dati riservati del referente", self.body)
        self.assertIn("Solo admin", self.body)
        self.assertIn("referente_nome", self.body)
        self.assertIn("referente_email", self.body)
        self.assertIn("Contatta il referente", self.body)
        self.assertIn("referente_email')|urlencode", self.body)

    def test_response_consents_and_timeline_are_visible(self):
        for field in (
            "esperienza_diretta",
            "testo_referente",
            "autorizza_pubblicazione",
            "autorizza_testo_pubblico",
            "timeline",
        ):
            self.assertIn(field, self.body)
        self.assertIn("Risposta, consensi e decisione", self.body)
        self.assertIn("Pubblicazione testo libero autorizzata", self.body)

    def test_admin_decision_form_has_expected_contract(self):
        self.assertIn(
            "url_for('admin_referenza_verifica', referenza_id=referenza.get('id'))",
            self.body,
        )
        self.assertIn('name="csrf_token"', self.body)
        self.assertIn('name="versione"', self.body)
        self.assertIn('name="stato_verifica"', self.body)
        self.assertIn('value="verificata"', self.body)
        self.assertIn('value="non_confermata"', self.body)
        self.assertIn('value="non_verificabile"', self.body)
        self.assertIn('name="metodo_verifica"', self.body)
        self.assertIn('value="email"', self.body)
        self.assertNotIn('value="telefono"', self.body)
        self.assertIn('value="email"', self.body)
        self.assertIn('value="altro"', self.body)
        self.assertIn('name="nota_admin"', self.body)
        self.assertIn('name="nota_pubblica"', self.body)

    def test_publication_approval_is_separate_from_contact_outcome(self):
        self.assertIn('name="pubblicazione_approvata_admin"', self.body)
        self.assertIn("Approva la visualizzazione pubblica", self.body)
        self.assertIn("Decisione editoriale finale", self.body)
        self.assertIn("data-public-consent=", self.body)
        self.assertIn("blockedByOutcome", self.body)
        self.assertIn("presenza di un nome", self.body)

    def test_contact_consent_and_retention_are_explicit(self):
        self.assertIn('data-contact-status="pending"', self.body)
        self.assertIn('data-contact-status="denied"', self.body)
        self.assertIn('data-contact-status="removed"', self.body)
        self.assertIn("non ha autorizzato MyLocalCare a ricontattarlo", self.body)
        self.assertIn("rimossi alla", self.body)
        self.assertIn("periodo di conservazione", self.body)
        self.assertIn("contatto_purged_at", self.body)
        self.assertIn("contatto_purge_at", self.body)

    def test_without_contact_only_non_verifiable_and_no_method_are_enabled(self):
        self.assertIn('data-contact-available=', self.body)
        self.assertIn(
            'name="metodo_verifica" value="nessuno"',
            self.body,
        )
        self.assertIn('<option value="nessuno"', self.body)
        self.assertIn(
            "if (state) state.value = \"non_verificabile\"",
            self.body,
        )
        self.assertIn("method.value = \"nessuno\"", self.body)
        self.assertIn("contactOutcomes", self.body)

    def test_pending_cards_do_not_look_like_completed_checks(self):
        self.assertIn("Invito aperto", self.body)
        self.assertIn("Invito inviato", self.body)
        self.assertIn("Invito scaduto", self.body)
        self.assertIn("In attesa della risposta del referente", self.body)
        self.assertIn(
            "Nessun esito amministrativo disponibile finché il referente non risponde.",
            self.body,
        )
        self.assertIn("{% if risposta == 'risposta_ricevuta' %}", self.body)

    def test_admin_query_and_timeline_include_retention_information(self):
        self.assertIn("c.contatto_purge_at", self.app)
        self.assertIn("c.contatto_purged_at", self.app)
        self.assertIn(
            '"invito_aperto": "Invito aperto dal referente"',
            self.app,
        )
        self.assertIn('"contatti_rimossi_retention"', self.app)


if __name__ == "__main__":
    unittest.main()
