import ast
import copy
import re
import sqlite3
import unittest
from pathlib import Path

from jinja2 import Environment


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "app.py"
TEMPLATE_PATH = ROOT / "templates" / "admin_interessi.html"
LAYOUT_PATH = ROOT / "templates" / "layout_admin.html"
DASHBOARD_PATH = ROOT / "templates" / "admin_dashboard.html"


def load_admin_interazioni_function():
    source = APP_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    function_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "admin_interessi"
    )
    function_node = copy.deepcopy(function_node)
    function_node.decorator_list = []
    module = ast.fix_missing_locations(
        ast.Module(body=[function_node], type_ignores=[])
    )
    return module


class AdminInterazioniTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app_source = APP_PATH.read_text(encoding="utf-8")
        cls.template_source = TEMPLATE_PATH.read_text(encoding="utf-8")
        cls.layout_source = LAYOUT_PATH.read_text(encoding="utf-8")
        cls.dashboard_source = DASHBOARD_PATH.read_text(encoding="utf-8")

    def build_database(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript("""
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                username TEXT,
                nome TEXT,
                cognome TEXT,
                citta TEXT,
                foto_profilo TEXT,
                email TEXT,
                attivo INTEGER,
                sospeso INTEGER DEFAULT 0,
                disattivato_admin INTEGER DEFAULT 0,
                eliminato INTEGER DEFAULT 0,
                ruolo TEXT DEFAULT 'user'
            );
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                titolo TEXT,
                zona TEXT,
                provincia TEXT,
                stato TEXT
            );
            CREATE TABLE interessi_annunci (
                id INTEGER PRIMARY KEY,
                annuncio_id INTEGER NOT NULL,
                utente_interessato_id INTEGER NOT NULL,
                attivo INTEGER NOT NULL,
                updated_at TEXT,
                ultima_notifica_at TEXT,
                chat_opened_at TEXT
            );
            CREATE TABLE messaggi_chat (
                id INTEGER PRIMARY KEY,
                mittente_id INTEGER NOT NULL,
                destinatario_id INTEGER NOT NULL,
                letto INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE recensioni (
                id INTEGER PRIMARY KEY,
                id_destinatario INTEGER NOT NULL,
                stato TEXT NOT NULL
            );
            CREATE TABLE risposte_recensioni (
                id INTEGER PRIMARY KEY,
                id_recensione INTEGER NOT NULL
            );
            CREATE TABLE notifiche (
                id INTEGER PRIMARY KEY,
                letta INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE richieste_disponibilita (
                id INTEGER PRIMARY KEY,
                annuncio_id INTEGER NOT NULL,
                richiedente_id INTEGER NOT NULL,
                offerente_id INTEGER NOT NULL,
                a_chiamata INTEGER NOT NULL DEFAULT 0,
                stato TEXT NOT NULL,
                created_at TEXT,
                updated_at TEXT,
                risposta_at TEXT
            );

            INSERT INTO utenti (
                id, username, nome, cognome, citta, foto_profilo, email,
                attivo
            ) VALUES
                (1, 'maria', 'Maria', 'Rossi', 'Milano', 'img/maria.jpg',
                 'maria@example.test', 1),
                (2, 'luca', 'Luca', 'Bianchi', 'Monza', 'img/luca.jpg',
                 'luca@example.test', 1);

            INSERT INTO annunci (
                id, utente_id, titolo, zona, provincia, stato
            ) VALUES (
                10, 1, 'Aiuto a domicilio', 'Milano', 'MI', 'approvato'
            );

            INSERT INTO interessi_annunci (
                id, annuncio_id, utente_interessato_id, attivo,
                updated_at, ultima_notifica_at, chat_opened_at
            ) VALUES (
                20, 10, 2, 1, '2026-09-29 09:00:00',
                '2026-09-29 09:01:00', '2026-09-29 09:05:00'
            );

            INSERT INTO messaggi_chat (
                id, mittente_id, destinatario_id, letto
            ) VALUES (30, 2, 1, 0);

            INSERT INTO recensioni (id, id_destinatario, stato)
            VALUES (31, 1, 'approvato');
            INSERT INTO risposte_recensioni (id, id_recensione)
            VALUES (32, 31);
            INSERT INTO notifiche (id, letta)
            VALUES (33, 0);

            INSERT INTO richieste_disponibilita (
                id, annuncio_id, richiedente_id, offerente_id, a_chiamata,
                stato, created_at, updated_at, risposta_at
            ) VALUES (
                40, 10, 2, 1, 1, 'disponibile',
                '2026-09-29 10:00:00', '2026-09-29 10:05:00',
                '2026-09-29 10:05:00'
            );
        """)
        return connection

    def run_admin_function(self, connection):
        rendered = {}

        def fake_render_template(template_name, **context):
            rendered["template_name"] = template_name
            rendered.update(context)
            return rendered

        def fake_url_for(endpoint, **values):
            if endpoint == "static":
                return f"/static/{values['filename']}"
            if endpoint == "profilo_pubblico":
                return f"/profilo/{values['id']}"
            return f"/{endpoint}"

        namespace = {
            "app": type(
                "FakeApp",
                (),
                {"config": {"IS_POSTGRES": False}},
            )(),
            "get_db_connection": lambda: connection,
            "get_cursor": lambda conn: conn.cursor(),
            "sql": lambda query: query,
            "url_for": fake_url_for,
            "render_template": fake_render_template,
            "carica_statistiche_accessi": lambda conn, **kwargs: {
                "oggi": 2,
                "settimana": 5,
                "mese": 9,
                "anonimi_oggi": 3,
                "anonimi_settimana": 8,
                "anonimi_mese": 14,
                "serie": [],
                "picco": 2,
                "zone": [],
                "giorni_con_dati": 3,
            },
            "log_exception_safe": lambda *args, **kwargs: None,
        }
        exec(compile(load_admin_interazioni_function(), str(APP_PATH), "exec"), namespace)
        return namespace["admin_interessi"]()

    def test_backend_combines_interest_and_availability_data(self):
        result = self.run_admin_function(self.build_database())

        self.assertEqual(result["template_name"], "admin_interessi.html")
        self.assertEqual(result["statistiche"]["attivi"], 1)
        self.assertEqual(result["statistiche"]["chat_aperte"], 1)
        self.assertEqual(
            result["annunci_piu_interessanti"][0]["zona_annuncio"],
            "Milano",
        )
        self.assertEqual(
            result["annunci_piu_interessanti"][0]["interessati"][0]["citta"],
            "Monza",
        )

        self.assertEqual(result["statistiche_richieste"]["totale"], 1)
        self.assertEqual(result["statistiche_richieste"]["disponibili"], 1)
        self.assertEqual(result["statistiche_richieste"]["con_risposta"], 1)
        request_card = result["richieste_disponibilita"][0]
        self.assertEqual(request_card["stato_label"], "Disponibile")
        self.assertEqual(request_card["richiedente"]["username"], "luca")
        self.assertEqual(request_card["richiedente"]["zona"], "Monza")
        self.assertEqual(request_card["offerente"]["username"], "maria")
        self.assertEqual(request_card["offerente"]["zona"], "Milano")
        self.assertEqual(request_card["annuncio_zona"], "Milano")
        self.assertEqual(request_card["annuncio_stato"], "approvato")
        self.assertTrue(result["accessi_disponibili"])
        self.assertEqual(result["statistiche_accessi"]["mese"], 9)
        self.assertEqual(result["statistiche_accessi"]["anonimi_mese"], 14)
        self.assertEqual(result["statistiche_generali"]["utenti_attivi"], 2)
        self.assertEqual(result["statistiche_generali"]["annunci_totali"], 1)
        self.assertEqual(result["statistiche_generali"]["chat_totali"], 1)
        self.assertEqual(result["statistiche_generali"]["messaggi_inviati"], 1)
        self.assertEqual(result["statistiche_generali"]["utenti_recensiti"], 1)

    def test_page_and_navigation_use_broader_interactions_name(self):
        self.assertIn("<h1>Interazioni</h1>", self.template_source)
        self.assertIn("<span>Interazioni</span>", self.layout_source)
        self.assertNotIn("<span>Interazioni annunci</span>", self.layout_source)
        self.assertNotIn("<span>Interessi annunci</span>", self.layout_source)
        self.assertNotIn("<span>Statistiche</span>", self.layout_source)
        self.assertIn('@app.route("/admin/interazioni")', self.app_source)
        self.assertIn('@app.route("/admin/interessi")', self.app_source)
        self.assertIn("current.startswith('/admin/interazioni')", self.layout_source)
        self.assertIn("url_for('admin_interessi')", self.dashboard_source)
        self.assertNotIn("url_for('admin_statistiche')", self.dashboard_source)
        self.assertIn('redirect(url_for("admin_interessi") + "#panoramica")', self.app_source)

    def test_availability_section_shows_counts_people_avatars_and_zones(self):
        for marker in (
            "statistiche_richieste.totale",
            "statistiche_richieste.in_attesa",
            "statistiche_richieste.con_risposta",
            "richiesta.richiedente.avatar_url",
            "richiesta.offerente.avatar_url",
            "richiesta.richiedente.zona",
            "richiesta.offerente.zona",
            "richiesta.annuncio_zona",
            "Ha chiesto",
            "Ha ricevuto",
        ):
            self.assertIn(marker, self.template_source)
        self.assertIn("LIMIT 100", self.app_source)
        self.assertIn("i conteggi sopra comprendono tutto lo storico", self.template_source)
        self.assertIn("a.stato AS annuncio_stato", self.app_source)
        self.assertIn("richiesta.annuncio_stato == 'approvato'", self.template_source)

    def test_interest_ranking_exposes_listing_and_person_zone(self):
        self.assertIn("annuncio.zona_annuncio", self.template_source)
        self.assertIn("Zona persona: {{ persona.citta }}", self.template_source)
        self.assertIn("a.zona AS zona_annuncio", self.app_source)

    def test_template_has_valid_jinja_syntax(self):
        Environment().parse(self.template_source)

    def test_access_panel_has_unique_counts_chart_and_zones(self):
        for marker in (
            "Collegamenti a MyLocalCare",
            "statistiche_accessi.oggi",
            "statistiche_accessi.settimana",
            "statistiche_accessi.mese",
            "statistiche_accessi.serie",
            "statistiche_accessi.zone",
            "ultimi 30 giorni",
            "Dati aggregati",
        ):
            self.assertIn(marker, self.template_source)

    def test_page_has_three_accessible_persistent_tab_panels(self):
        self.assertEqual(self.template_source.count('role="tab"'), 3)
        self.assertEqual(self.template_source.count('role="tabpanel"'), 3)
        self.assertEqual(self.template_source.count('type="button"'), 3)
        for label in ("Panoramica", "Interessi", "Disponibilità"):
            self.assertIn(f"<strong>{label}</strong>", self.template_source)

        panel_openings = re.findall(
            r'<div\s+class="admin-interaction-tab-panel".*?>',
            self.template_source,
            flags=re.DOTALL,
        )
        self.assertEqual(len(panel_openings), 3)
        self.assertEqual(sum(" hidden" in panel for panel in panel_openings), 2)

        for section in (
            "panoramica",
            "interessi",
            "richieste-disponibilita",
        ):
            tab_id = f"admin-interaction-tab-{section}"
            panel_id = f"admin-interaction-panel-{section}"
            self.assertIn(f'id="{tab_id}"', self.template_source)
            self.assertIn(
                f'aria-controls="{panel_id}"',
                self.template_source,
            )
            self.assertIn(f'id="{panel_id}"', self.template_source)
            self.assertIn(
                f'aria-labelledby="{tab_id}"',
                self.template_source,
            )

        self.assertIn('aria-selected="true"', self.template_source)
        self.assertEqual(self.template_source.count('aria-selected="false"'), 2)
        self.assertIn("window.history.pushState", self.template_source)
        self.assertIn('window.addEventListener("hashchange"', self.template_source)
        for keyboard_key in ("ArrowRight", "ArrowLeft", "Home", "End"):
            self.assertIn(keyboard_key, self.template_source)

    def test_overview_contains_all_legacy_statistics_and_live_refresh(self):
        for counter in (
            "utenti_attivi",
            "annunci_totali",
            "utenti_con_annunci",
            "utenti_senza_annunci",
            "utenti_recensiti",
            "recensioni_con_risposta",
            "chat_totali",
            "messaggi_inviati",
            "messaggi_non_letti",
            "notifiche_ricevute",
            "notifiche_da_leggere",
        ):
            self.assertIn(
                f'data-counter="statistiche.{counter}"',
                self.template_source,
            )
        self.assertIn('fetch("/admin/counters"', self.template_source)
        self.assertIn('data-derived-stat="read-rate"', self.template_source)
        self.assertIn('data-derived-stat="messages-per-chat"', self.template_source)

    def test_interest_cards_keep_compact_mobile_rows(self):
        self.assertIn(
            "grid-template-columns: 30px minmax(0, 1fr) auto;",
            self.template_source,
        )
        self.assertIn("grid-column: auto;", self.template_source)
        self.assertIn(
            "grid-template-columns: minmax(0, 1fr) 18px minmax(0, 1fr);",
            self.template_source,
        )
        self.assertNotIn(
            ".admin-availability-people {\n      grid-template-columns: 1fr;",
            self.template_source,
        )

    def test_access_panel_separates_registered_users_from_anonymous_estimates(self):
        for marker in (
            "Utenti registrati",
            "persone uniche con account",
            "Visitatori non registrati",
            "visite/sessioni stimate, non persone certe",
            "statistiche_accessi.anonimi_oggi",
            "statistiche_accessi.anonimi_settimana",
            "statistiche_accessi.anonimi_mese",
            "punto.anonimi|default(0, true)",
            "Zone utenti registrati",
            "chi visita il sito e poi accede può comparire in entrambe",
        ):
            self.assertIn(marker, self.template_source)


if __name__ == "__main__":
    unittest.main()
