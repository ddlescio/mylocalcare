from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAYOUT = ROOT / "templates" / "layout_admin.html"
DASHBOARD = ROOT / "templates" / "admin_dashboard.html"
APP = ROOT / "app.py"


class AdminReferenzeNavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = LAYOUT.read_text(encoding="utf-8")
        cls.dashboard = DASHBOARD.read_text(encoding="utf-8")
        cls.app = APP.read_text(encoding="utf-8")

    def test_sidebar_links_queue_and_exposes_live_badge(self):
        self.assertIn("url_for('admin_referenze')", self.layout)
        self.assertIn('id="badge-referenze"', self.layout)
        self.assertIn("data.referenze_da_verificare", self.layout)
        self.assertIn("current.startswith('/admin/referenze')", self.layout)

    def test_dashboard_has_reference_queue_card_and_counter_updates(self):
        self.assertIn('id="card-referenze-alert"', self.dashboard)
        self.assertIn('id="dash-referenze"', self.dashboard)
        self.assertIn("Referenze da controllare", self.dashboard)
        self.assertIn(
            'setText("dash-referenze", data.referenze_da_verificare)',
            self.dashboard,
        )
        self.assertIn(
            'setAlertCard("card-referenze-alert", data.referenze_da_verificare)',
            self.dashboard,
        )

    def test_counter_counts_only_received_references_waiting_for_review(self):
        self.assertIn('step = "referenze"', self.app)
        self.assertIn("FROM referenze", self.app)
        self.assertIn("stato_risposta = 'risposta_ricevuta'", self.app)
        self.assertIn(
            "stato_verifica IN ('non_esaminata', 'in_coda')",
            self.app,
        )

    def test_counter_is_rollout_tolerant_and_present_in_fallback(self):
        self.assertIn(
            '"Referenze non ancora disponibili nei contatori admin"',
            self.app,
        )
        self.assertGreaterEqual(
            self.app.count('"referenze_da_verificare":'),
            2,
        )
        self.assertIn("+ referenze_da_verificare", self.app)


if __name__ == "__main__":
    unittest.main()
