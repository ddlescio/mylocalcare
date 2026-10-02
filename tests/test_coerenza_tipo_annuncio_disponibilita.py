import ast
import re
import sqlite3
import unicodedata
import unittest
from pathlib import Path
from types import SimpleNamespace

from annuncio_disponibilita import request_to_service_availability
from disponibilita_servizi import normalize_disponibilita_payload


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
MODELS_SOURCE = (ROOT / "models.py").read_text(encoding="utf-8")


def _source(name):
    tree = ast.parse(APP_SOURCE)
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return ast.get_source_segment(APP_SOURCE, node)


def _models_source(name):
    tree = ast.parse(MODELS_SOURCE)
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return ast.get_source_segment(MODELS_SOURCE, node)


def _load_function(name, namespace):
    tree = ast.parse(APP_SOURCE)
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    node.decorator_list = []
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    return namespace[name]


def _assignment_expression(function_name, target_name):
    tree = ast.parse(APP_SOURCE)
    function = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == function_name
    )
    assignment = next(
        item
        for item in ast.walk(function)
        if isinstance(item, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == target_name
            for target in item.targets
        )
    )
    return ast.fix_missing_locations(ast.Expression(body=assignment.value))


class CoerenzaTipoAnnuncioDisponibilitaTest(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()
        self.cur.executescript("""
            CREATE TABLE annunci (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria TEXT NOT NULL,
                tipo_annuncio TEXT NOT NULL,
                stato TEXT NOT NULL
            );
            CREATE TABLE disponibilita_profili_categoria (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                versione INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE disponibilita_profili (
                utente_id INTEGER PRIMARY KEY,
                versione INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE annunci_disponibilita_ciclo (
                annuncio_id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL
            );
            CREATE TABLE annunci_disponibilita_eventi (
                id INTEGER PRIMARY KEY,
                annuncio_id INTEGER NOT NULL
            );
        """)

    def tearDown(self):
        self.conn.close()

    def _cleanup_function(self, reminders):
        namespace = {
            "sql": lambda query: query,
            "to_slug": lambda value: str(value or "").strip().lower(),
            "_disponibilita_categoria_slug": (
                lambda value: str(value or "").strip().lower()
            ),
            "_annunci_disponibilita_ciclo_tables_exist": lambda cur: True,
            "_disponibilita_categoria_table_exists": lambda cur: True,
            "_disponibilita_servizi_table_exists": lambda cur: True,
            "_annulla_promemoria_disponibilita_pendenti": (
                lambda cur, user_id, categoria_slug=None: reminders.append(
                    (user_id, categoria_slug)
                )
            ),
            "_elimina_disponibilita_categoria": (
                lambda cur, user_id, categoria_slug: cur.execute(
                    """
                    DELETE FROM disponibilita_profili_categoria
                    WHERE utente_id = ? AND categoria_slug = ?
                    """,
                    (user_id, categoria_slug),
                )
            ),
            "_elimina_disponibilita_generale": (
                lambda cur, user_id: bool(cur.execute(
                    "DELETE FROM disponibilita_profili WHERE utente_id = ?",
                    (user_id,),
                ).rowcount)
            ),
        }
        return _load_function(
            "_rimuovi_disponibilita_collegata_annuncio",
            namespace,
        )

    def _admin_type_route(self, requested_type, cleanups, initializations):
        namespace = {
            "request": SimpleNamespace(
                get_json=lambda silent=True: {
                    "tipo_annuncio": requested_type,
                }
            ),
            "verify_csrf": lambda: None,
            "get_db_connection": lambda: self.conn,
            "get_cursor": lambda connection: connection.cursor(),
            "sql": lambda query: query,
            "_disponibilita_categoria_annuncio_sql": (
                lambda column: f"LOWER(TRIM({column}))"
            ),
            "_disponibilita_categoria_slug": (
                lambda value: str(value or "").strip().lower()
            ),
            "jsonify": lambda **payload: payload,
            "_rimuovi_disponibilita_collegata_annuncio": (
                lambda cur, user_id, annuncio_id, categoria: cleanups.append(
                    (user_id, annuncio_id, categoria)
                )
            ),
            "_imposta_disponibilita_default_annuncio_offro": (
                lambda cur, user_id, annuncio_id, categoria, **kwargs: (
                    initializations.append(
                        (user_id, annuncio_id, categoria, kwargs)
                    )
                )
            ),
        }
        return _load_function("admin_annuncio_tipo", namespace)

    def test_cambio_offro_cerco_rimuove_profilo_ciclo_ed_eventi(self):
        self.cur.execute(
            "INSERT INTO annunci VALUES (1, 7, 'babysitter', 'cerco', 'approvato')"
        )
        self.cur.execute(
            "INSERT INTO disponibilita_profili_categoria VALUES (4, 7, 'babysitter', 3)"
        )
        self.cur.execute(
            "INSERT INTO disponibilita_profili VALUES (7, 2)"
        )
        self.cur.execute(
            "INSERT INTO annunci_disponibilita_ciclo VALUES (1, 7)"
        )
        self.cur.execute(
            "INSERT INTO annunci_disponibilita_eventi VALUES (9, 1)"
        )
        reminders = []

        removed = self._cleanup_function(reminders)(
            self.cur, 7, 1, "babysitter"
        )

        self.assertTrue(removed)
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM disponibilita_profili_categoria"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM disponibilita_profili"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM annunci_disponibilita_ciclo"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM annunci_disponibilita_eventi"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            reminders,
            [(7, "babysitter"), (7, None)],
        )

    def test_offerta_disattivata_non_trattiene_la_disponibilita(self):
        self.cur.executemany(
            "INSERT INTO annunci VALUES (?, 7, 'babysitter', ?, ?)",
            (
                (1, "cerco", "approvato"),
                (2, "offro", "disattivato"),
            ),
        )
        self.cur.execute(
            "INSERT INTO disponibilita_profili_categoria VALUES (4, 7, 'babysitter', 3)"
        )
        self.cur.execute(
            "INSERT INTO annunci_disponibilita_ciclo VALUES (1, 7)"
        )
        reminders = []

        removed = self._cleanup_function(reminders)(
            self.cur, 7, 1, "babysitter"
        )

        self.assertTrue(removed)
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM disponibilita_profili_categoria"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM annunci_disponibilita_ciclo"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            reminders,
            [(7, "babysitter"), (7, None)],
        )

    def test_profilo_categoria_resta_se_esiste_un_altra_offerta_pubblicabile(self):
        self.cur.executemany(
            "INSERT INTO annunci VALUES (?, 7, 'babysitter', ?, ?)",
            (
                (1, "cerco", "approvato"),
                (2, "offro", "in_attesa"),
            ),
        )
        self.cur.execute(
            "INSERT INTO disponibilita_profili_categoria VALUES (4, 7, 'babysitter', 3)"
        )
        self.cur.execute(
            "INSERT INTO disponibilita_profili VALUES (7, 2)"
        )
        reminders = []

        removed = self._cleanup_function(reminders)(
            self.cur, 7, 1, "babysitter"
        )

        self.assertFalse(removed)
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM disponibilita_profili_categoria"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.cur.execute(
                "SELECT COUNT(*) FROM disponibilita_profili"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(reminders, [])

    def test_nuova_offerta_parte_disponibile_e_avvia_ciclo_se_approvata(self):
        saves = []
        resets = []
        namespace = {
            "sql": lambda query: query,
            "to_slug": lambda value: str(value or "").strip().lower(),
            "_disponibilita_categoria_slug": (
                lambda value: str(value or "").strip().lower()
            ),
            "_disponibilita_categoria_table_exists": lambda cur: True,
            "normalize_disponibilita_payload": normalize_disponibilita_payload,
            "request_to_service_availability": request_to_service_availability,
            "_salva_disponibilita_categoria": (
                lambda *args, **kwargs: saves.append((args, kwargs))
            ),
            "_reset_ciclo_disponibilita_annunci": (
                lambda *args, **kwargs: resets.append((args, kwargs))
            ),
            "RuntimeError": RuntimeError,
        }
        initialize = _load_function(
            "_imposta_disponibilita_default_annuncio_offro",
            namespace,
        )

        payload = initialize(
            self.cur,
            7,
            1,
            "babysitter",
            stato_annuncio="approvato",
        )

        self.assertEqual(payload["stato"], "disponibile")
        self.assertFalse(payload["a_chiamata"])
        self.assertEqual(payload["settimanale"], [])
        self.assertEqual(payload["settimanale_intervalli"], [])
        self.assertFalse(saves[0][1]["preserve_calendar_exceptions"])
        self.assertEqual(resets[0][1]["annuncio_id"], 1)
        self.assertEqual(resets[0][1]["stato_disponibilita"], "disponibile")

    def test_admin_cerco_offro_inizializza_disponibilita_e_ciclo(self):
        self.cur.execute(
            "ALTER TABLE annunci ADD COLUMN disponibilita_cercata_json TEXT"
        )
        self.cur.execute(
            """
            INSERT INTO annunci (
                id, utente_id, categoria, tipo_annuncio, stato,
                disponibilita_cercata_json
            ) VALUES (10, 7, 'babysitter', 'cerco', 'approvato', '{}')
            """
        )
        cleanups = []
        initializations = []

        response = self._admin_type_route(
            "offro", cleanups, initializations
        )(10)

        listing = self.cur.execute(
            """
            SELECT tipo_annuncio, stato, disponibilita_cercata_json
            FROM annunci WHERE id = 10
            """
        ).fetchone()
        self.assertTrue(response["ok"])
        self.assertEqual(listing["tipo_annuncio"], "offro")
        self.assertEqual(listing["stato"], "approvato")
        self.assertIsNone(listing["disponibilita_cercata_json"])
        self.assertEqual(cleanups, [])
        self.assertEqual(
            initializations,
            [(7, 10, "babysitter", {"stato_annuncio": "approvato"})],
        )

    def test_admin_cerco_offro_inattivo_attende_la_riattivazione(self):
        self.cur.execute(
            "ALTER TABLE annunci ADD COLUMN disponibilita_cercata_json TEXT"
        )
        cleanups = []
        initializations = []

        for listing_id, previous_state in (
            (12, "disattivato"),
            (13, "rifiutato"),
        ):
            with self.subTest(previous_state=previous_state):
                self.cur.execute("""
                    INSERT INTO annunci (
                        id, utente_id, categoria, tipo_annuncio, stato,
                        disponibilita_cercata_json
                    ) VALUES (?, 7, 'babysitter', 'cerco', ?, '{}')
                """, (listing_id, previous_state))

                response = self._admin_type_route(
                    "offro", cleanups, initializations
                )(listing_id)

                listing = self.cur.execute("""
                    SELECT tipo_annuncio, stato, disponibilita_cercata_json
                    FROM annunci WHERE id = ?
                """, (listing_id,)).fetchone()
                self.assertTrue(response["ok"])
                self.assertEqual(listing["tipo_annuncio"], "offro")
                self.assertEqual(listing["stato"], previous_state)
                self.assertIsNone(listing["disponibilita_cercata_json"])

        # Un annuncio non utilizzabile non deve avviare in anticipo la data
        # di conferma. L'approvazione lo inizializzera da quel momento.
        self.assertEqual(cleanups, [])
        self.assertEqual(initializations, [])

    def test_admin_offro_cerco_riattiva_annuncio_archiviato(self):
        self.cur.execute(
            "ALTER TABLE annunci ADD COLUMN disponibilita_cercata_json TEXT"
        )
        self.cur.execute(
            """
            INSERT INTO annunci (
                id, utente_id, categoria, tipo_annuncio, stato,
                disponibilita_cercata_json
            ) VALUES (
                11, 7, 'babysitter', 'offro',
                'archiviato_disponibilita', NULL
            )
            """
        )
        cleanups = []
        initializations = []

        response = self._admin_type_route(
            "cerco", cleanups, initializations
        )(11)

        listing = self.cur.execute(
            "SELECT tipo_annuncio, stato FROM annunci WHERE id = 11"
        ).fetchone()
        self.assertTrue(response["ok"])
        self.assertEqual(listing["tipo_annuncio"], "cerco")
        self.assertEqual(listing["stato"], "approvato")
        self.assertEqual(cleanups, [(7, 11, "babysitter")])
        self.assertEqual(initializations, [])

    def test_route_canonicalizza_alias_prima_di_confrontare_e_salvare(self):
        namespace = {
            "re": re,
            "unicodedata": unicodedata,
            "CATEGORY_MAP": {
                "escursioni-sport": ("escursioni-sport", "Sport"),
                "sport": ("escursioni-sport", "Sport"),
            },
        }
        namespace["to_slug"] = _load_function("to_slug", namespace)
        canonicalize = _load_function(
            "_disponibilita_categoria_slug",
            namespace,
        )

        edit_category = eval(
            compile(
                _assignment_expression("modifica_annuncio", "categoria"),
                "app.py",
                "eval",
            ),
            {"_disponibilita_categoria_slug": canonicalize},
            {"raw_categoria": "escursioni-sport"},
        )
        previous_category = eval(
            compile(
                _assignment_expression(
                    "modifica_annuncio",
                    "categoria_precedente",
                ),
                "app.py",
                "eval",
            ),
            {"_disponibilita_categoria_slug": canonicalize},
            {"annuncio": {"categoria": "Sport"}},
        )
        create_category = eval(
            compile(
                _assignment_expression("nuovo_annuncio", "categoria"),
                "app.py",
                "eval",
            ),
            {"_disponibilita_categoria_slug": canonicalize},
            {"categoria_raw": "Sport"},
        )

        self.assertEqual(edit_category, "escursioni-sport")
        self.assertEqual(previous_category, edit_category)
        self.assertEqual(create_category, "escursioni-sport")

        category_sql = _load_function(
            "_disponibilita_categoria_annuncio_sql",
            {},
        )("categoria")
        self.cur.execute(
            f"SELECT 1 FROM annunci WHERE ({category_sql}) = ? LIMIT 1",
            (create_category,),
        )
        self.assertIsNone(self.cur.fetchone())
        self.cur.execute(
            "INSERT INTO annunci VALUES (12, 7, 'Sport', 'offro', 'approvato')"
        )
        self.cur.execute(
            f"SELECT 1 FROM annunci WHERE ({category_sql}) = ? LIMIT 1",
            (create_category,),
        )
        self.assertIsNotNone(self.cur.fetchone())

    def test_tutti_i_percorsi_mutanti_usano_la_sincronizzazione(self):
        admin = _source("admin_annuncio_tipo")
        edit = _source("modifica_annuncio")
        delete_html = _source("elimina_annuncio")
        delete_api = _source("elimina_annuncio_api")
        reject = _source("rifiuta_annuncio")
        approve = _source("_approva_annuncio_con_disponibilita")
        toggle = _source("toggle_annuncio")

        self.assertIn("_rimuovi_disponibilita_collegata_annuncio", admin)
        self.assertIn("_imposta_disponibilita_default_annuncio_offro", admin)
        self.assertIn("_rimuovi_disponibilita_collegata_annuncio", edit)
        self.assertIn("_rimuovi_disponibilita_collegata_annuncio", delete_html)
        self.assertIn("_rimuovi_disponibilita_collegata_annuncio", delete_api)
        self.assertIn("disponibilita_cercata_json = NULL", delete_html)
        self.assertIn("disponibilita_cercata_json = NULL", delete_api)
        self.assertIn("_rimuovi_disponibilita_collegata_annuncio", reject)
        self.assertIn("_rimuovi_disponibilita_collegata_annuncio", toggle)
        self.assertIn("verify_csrf()", toggle)
        self.assertIn(
            '@app.route("/admin/annunci/toggle/<int:id>", methods=["POST"])',
            APP_SOURCE,
        )
        self.assertIn("_reset_ciclo_disponibilita_annunci", approve)
        self.assertIn("annuncio_id=int(annuncio_id)", approve)

    def test_eliminazione_account_admin_bonifica_tutte_le_disponibilita(self):
        admin_account_delete = _models_source("elimina_utente")

        for table in (
            "disponibilita_settimanale",
            "disponibilita_intervalli",
            "disponibilita_date_speciali",
            "disponibilita_assenze",
            "disponibilita_profili_categoria",
            "disponibilita_profili",
        ):
            self.assertIn(table, admin_account_delete)
        self.assertLess(
            admin_account_delete.index("availability_table_names"),
            admin_account_delete.index("DELETE FROM annunci"),
        )


if __name__ == "__main__":
    unittest.main()
