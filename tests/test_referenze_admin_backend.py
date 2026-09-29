import ast
import copy
import json
import sqlite3
import unittest
from pathlib import Path
from types import SimpleNamespace

from i18n import normalize_language, translate, translate_source
from referenze import contains_direct_contact


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)


def _app_node(name, node_type=ast.FunctionDef):
    for node in APP_TREE.body:
        if isinstance(node, node_type) and getattr(node, "name", None) == name:
            selected = copy.deepcopy(node)
            if isinstance(selected, (ast.FunctionDef, ast.AsyncFunctionDef)):
                selected.decorator_list = []
            return selected
    raise AssertionError(f"Nodo {name} non trovato in app.py")


def _load_pure_helpers():
    wanted_constants = {
        "REFERENCE_ADMIN_FILTER_STATES",
        "REFERENCE_ADMIN_DECISION_STATES",
        "REFERENCE_ADMIN_CONTACT_METHODS",
        "REFERENCE_ADMIN_METHODS",
    }
    nodes = []
    for node in APP_TREE.body:
        if isinstance(node, ast.Assign):
            names = {
                target.id
                for target in node.targets
                if isinstance(target, ast.Name)
            }
            if names & wanted_constants:
                nodes.append(copy.deepcopy(node))
    nodes.extend([
        _app_node("_referenza_admin_filter_clause"),
        _app_node("_referenza_admin_validate_decision"),
        _app_node("_referenza_admin_evento_presentato"),
    ])
    namespace = {
        "CATEGORIE_SERVIZI": ("babysitter", "caregiver", "pet-sitter"),
        "reference_contains_direct_contact": contains_direct_contact,
        "json": json,
        "_referenze_iso": lambda value: None if value is None else str(value),
    }
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), "app.py", "exec"),
        namespace,
    )
    return namespace


class ReferenzeAdminValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = _load_pure_helpers()

    def valid_reference(self, **changes):
        reference = {
            "stato_risposta": "risposta_ricevuta",
            "autorizza_contatto_verifica": 1,
            "autorizza_pubblicazione": 1,
            "esperienza_diretta": 1,
            "telefono_cifrato": "cipher",
            "telefono_nonce": "nonce",
            "telefono_tag": "tag",
            "contatto_purged_at": None,
        }
        reference.update(changes)
        return reference

    def test_filter_maps_only_known_states_and_categories(self):
        build = self.backend["_referenza_admin_filter_clause"]

        pending = build("da_gestire", "babysitter")
        self.assertIn("stato_verifica IN", pending["sql"])
        self.assertIn("categoria_slug = ?", pending["sql"])
        self.assertEqual(pending["params"], ("babysitter",))

        expired = build("scaduta", "tutte")
        self.assertIn("token_expires_at <= CURRENT_TIMESTAMP", expired["sql"])

        invalid = build("DROP TABLE referenze", "categoria-inesistente")
        self.assertEqual(invalid["stato"], "da_gestire")
        self.assertEqual(invalid["categoria"], "tutte")
        self.assertEqual(invalid["params"], ())

    def test_positive_or_negative_check_requires_contact_consent(self):
        validate = self.backend["_referenza_admin_validate_decision"]
        without_consent = self.valid_reference(
            autorizza_contatto_verifica=0,
        )

        for state in ("verificata", "non_confermata"):
            with self.subTest(state=state), self.assertRaisesRegex(
                ValueError, "non ha autorizzato il contatto"
            ):
                validate(
                    without_consent,
                    stato=state,
                    metodo="telefono",
                    nota_admin="Riscontro effettuato",
                    nota_pubblica="",
                )

        decision = validate(
            without_consent,
            stato="non_verificabile",
            metodo="nessuno",
            nota_admin="Il referente non autorizza il contatto.",
            nota_pubblica="",
        )
        self.assertEqual(decision["stato"], "non_verificabile")
        self.assertEqual(decision["metodo"], "nessuno")

    def test_verified_requires_direct_experience_and_real_contact_method(self):
        validate = self.backend["_referenza_admin_validate_decision"]
        self.assertEqual(
            self.backend["REFERENCE_ADMIN_CONTACT_METHODS"],
            {"telefono"},
        )
        with self.assertRaisesRegex(ValueError, "Indica come"):
            validate(
                self.valid_reference(),
                stato="verificata",
                metodo="nessuno",
                nota_admin="",
                nota_pubblica="",
            )

        telephone = validate(
            self.valid_reference(),
            stato="verificata",
            metodo="telefono",
            nota_admin="Contatto telefonico concluso",
            nota_pubblica="",
        )
        self.assertEqual(telephone["metodo"], "telefono")
        with self.assertRaisesRegex(ValueError, "Metodo di controllo"):
            validate(
                self.valid_reference(),
                stato="verificata",
                metodo="email",
                nota_admin="",
                nota_pubblica="",
            )
        with self.assertRaisesRegex(ValueError, "esperienza diretta"):
            validate(
                self.valid_reference(esperienza_diretta=0),
                stato="verificata",
                metodo="telefono",
                nota_admin="",
                nota_pubblica="",
            )

    def test_purged_contact_can_only_be_marked_non_verifiable(self):
        validate = self.backend["_referenza_admin_validate_decision"]
        purged = self.valid_reference(
            contatto_purged_at="2026-09-28T10:00:00+00:00",
        )

        with self.assertRaisesRegex(ValueError, "dati di contatto"):
            validate(
                purged,
                stato="verificata",
                metodo="telefono",
                nota_admin="",
                nota_pubblica="",
            )

        decision = validate(
            purged,
            stato="non_verificabile",
            metodo="nessuno",
            nota_admin="Dati di contatto rimossi per scadenza retention.",
            nota_pubblica="",
        )
        self.assertEqual(decision["stato"], "non_verificabile")
        self.assertEqual(decision["metodo"], "nessuno")

    def test_missing_contact_data_can_only_be_marked_non_verifiable(self):
        validate = self.backend["_referenza_admin_validate_decision"]
        unavailable = self.valid_reference(
            telefono_cifrato=None,
            telefono_nonce=None,
            telefono_tag=None,
        )

        with self.assertRaisesRegex(ValueError, "dati di contatto"):
            validate(
                unavailable,
                stato="non_confermata",
                metodo="telefono",
                nota_admin="Il recapito non è disponibile.",
                nota_pubblica="",
            )

        decision = validate(
            unavailable,
            stato="non_verificabile",
            metodo="nessuno",
            nota_admin="Il recapito non è disponibile.",
            nota_pubblica="",
        )
        self.assertEqual(decision["stato"], "non_verificabile")

    def test_negative_results_require_internal_note(self):
        validate = self.backend["_referenza_admin_validate_decision"]
        for state in ("non_confermata", "non_verificabile"):
            with self.subTest(state=state), self.assertRaisesRegex(
                ValueError, "nota interna"
            ):
                validate(
                    self.valid_reference(),
                    stato=state,
                    metodo="telefono",
                    nota_admin="",
                    nota_pubblica="",
                )

    def test_public_note_rejects_direct_contacts(self):
        validate = self.backend["_referenza_admin_validate_decision"]
        for note in (
            "Scrivere a referente@example.test",
            "Telefonare al +39 333 123 4567",
            "Dettagli su https://example.test/profilo",
        ):
            with self.subTest(note=note), self.assertRaisesRegex(
                ValueError, "nota pubblica"
            ):
                validate(
                    self.valid_reference(),
                    stato="verificata",
                    metodo="telefono",
                    nota_admin="",
                    nota_pubblica=note,
                )

    def test_publication_approval_is_separate_and_requires_referee_consent(self):
        validate = self.backend["_referenza_admin_validate_decision"]
        approved = validate(
            self.valid_reference(),
            stato="non_verificabile",
            metodo="nessuno",
            nota_admin="Contatto non autorizzato.",
            nota_pubblica="",
            approva_pubblicazione="1",
        )
        self.assertTrue(approved["pubblicazione_approvata_admin"])

        denied = validate(
            self.valid_reference(autorizza_pubblicazione=0),
            stato="non_verificabile",
            metodo="nessuno",
            nota_admin="Contatto non autorizzato.",
            nota_pubblica="",
            approva_pubblicazione="1",
        )
        self.assertFalse(denied["pubblicazione_approvata_admin"])

        contradicted = validate(
            self.valid_reference(),
            stato="non_confermata",
            metodo="telefono",
            nota_admin="Il rapporto non è stato confermato.",
            nota_pubblica="",
            approva_pubblicazione="1",
        )
        self.assertFalse(
            contradicted["pubblicazione_approvata_admin"]
        )

    def test_timeline_never_exposes_internal_note_snapshot(self):
        present = self.backend["_referenza_admin_evento_presentato"]
        event = present({
            "tipo_evento": "verifica_admin_registrata",
            "created_at": "2026-09-28T10:00:00+00:00",
            "dettagli_snapshot": json.dumps({
                "stato_nuovo": "non_verificabile",
                "metodo": "nessuno",
                "nota_admin": "dato interno sensibile",
            }),
        })
        self.assertEqual(event["titolo"], "Esito admin registrato")
        self.assertIn("non verificabile", event["dettaglio"])
        self.assertNotIn("sensibile", event["dettaglio"])


class ReferenzeContactPresentationTest(unittest.TestCase):
    def test_phone_is_decrypted_only_for_admin_and_email_only_for_invite(self):
        function = _app_node("_referenza_decrypt_contact")
        namespace = {
            "decrypt_reference_email": lambda *args, **kwargs: (
                "invite@example.test"
            ),
            "decrypt_reference_name": lambda *args, **kwargs: "Mario Rossi",
            "decrypt_reference_phone": lambda *args, **kwargs: (
                "+39 333 123 4567"
            ),
            "decrypt_invitation_message": lambda *args, **kwargs: "",
            "MASTER_SECRET": bytes(range(32)),
            "REFERENCE_KEY_ID": "references-pii-v1",
            "log_exception_safe": lambda *args, **kwargs: None,
        }
        exec(
            compile(
                ast.Module(body=[function], type_ignores=[]),
                "app.py",
                "exec",
            ),
            namespace,
        )
        present = namespace["_referenza_decrypt_contact"]
        row = {
            "id": 9,
            "autorizza_contatto_verifica": 1,
            "email_cifrata": "email-cipher",
            "email_nonce": "email-nonce",
            "email_tag": "email-tag",
            "email_key_id": "references-pii-v1",
            "nome_cifrato": "name-cipher",
            "nome_nonce": "name-nonce",
            "nome_tag": "name-tag",
            "telefono_cifrato": "phone-cipher",
            "telefono_nonce": "phone-nonce",
            "telefono_tag": "phone-tag",
            "contatto_purged_at": None,
        }

        invitation_view = present(row)
        self.assertEqual(
            invitation_view["referente_email"],
            "invite@example.test",
        )
        self.assertEqual(invitation_view["referente_telefono"], "")

        admin_view = present(
            row,
            include_admin_phone=True,
            include_invitation_email=False,
        )
        self.assertEqual(admin_view["referente_email"], "")
        self.assertEqual(
            admin_view["referente_telefono"],
            "+39 333 123 4567",
        )

        no_consent = present(
            {**row, "autorizza_contatto_verifica": 0},
            include_admin_phone=True,
            include_invitation_email=False,
        )
        self.assertEqual(no_consent["referente_telefono"], "")


class ReferenzeAdminPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript("""
            CREATE TABLE referenze (
                id INTEGER PRIMARY KEY,
                utente_id INTEGER NOT NULL,
                categoria_slug TEXT NOT NULL,
                esperienza_diretta INTEGER NOT NULL,
                stato_risposta TEXT NOT NULL,
                stato_verifica TEXT NOT NULL,
                autorizza_contatto_verifica INTEGER NOT NULL DEFAULT 0,
                autorizza_pubblicazione INTEGER NOT NULL DEFAULT 0,
                pubblicazione_approvata_admin INTEGER NOT NULL DEFAULT 0,
                pubblicazione_approvata_at TEXT,
                pubblicazione_approvata_da_admin_id INTEGER,
                visibile_profilo INTEGER NOT NULL DEFAULT 1,
                verificata_at TEXT,
                revocata_at TEXT,
                cancellata_at TEXT,
                verificata_da_admin_id INTEGER,
                metodo_verifica TEXT NOT NULL DEFAULT 'nessuno',
                nota_admin TEXT,
                nota_pubblica TEXT,
                versione INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT
            );
            CREATE TABLE referenze_eventi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referenza_id INTEGER NOT NULL,
                tipo_evento TEXT NOT NULL,
                attore_tipo TEXT NOT NULL,
                attore_utente_id INTEGER,
                dettagli_snapshot TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE referenze_contatti (
                referenza_id INTEGER PRIMARY KEY,
                email_cifrata TEXT,
                email_nonce TEXT,
                email_tag TEXT,
                email_key_id TEXT,
                nome_cifrato TEXT,
                nome_nonce TEXT,
                nome_tag TEXT,
                telefono_cifrato TEXT,
                telefono_nonce TEXT,
                telefono_tag TEXT,
                contatto_purged_at TEXT
            );
            CREATE TABLE utenti (
                id INTEGER PRIMARY KEY,
                lingua_interfaccia TEXT NOT NULL DEFAULT 'it'
            );
        """)
        self.connection.execute("""
            INSERT INTO referenze (
                id, utente_id, categoria_slug, esperienza_diretta,
                stato_risposta, stato_verifica,
                autorizza_contatto_verifica, versione
            ) VALUES (
                10, 7, 'babysitter', 1,
                'risposta_ricevuta', 'in_coda', 1, 2
            )
        """)
        self.connection.execute("""
            INSERT INTO referenze_contatti (
                referenza_id, email_cifrata, email_nonce, email_tag,
                telefono_cifrato, telefono_nonce, telefono_tag,
                contatto_purged_at
            ) VALUES (
                10, 'email-cipher', 'email-nonce', 'email-tag',
                'phone-cipher', 'phone-nonce', 'phone-tag', NULL
            )
        """)
        self.connection.execute(
            "INSERT INTO utenti (id, lingua_interfaccia) VALUES (7, 'it')"
        )
        self.connection.commit()
        self.flashes = []
        self.notifications = []
        self.invalidations = []
        helpers = _load_pure_helpers()
        function = _app_node("admin_referenza_verifica")

        def event(cursor, reference_id, event_type, actor_type, **kwargs):
            cursor.execute("""
                INSERT INTO referenze_eventi (
                    referenza_id, tipo_evento, attore_tipo,
                    attore_utente_id, dettagli_snapshot
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                reference_id,
                event_type,
                actor_type,
                kwargs.get("attore_utente_id"),
                json.dumps(kwargs.get("dettagli") or {}, sort_keys=True),
            ))

        class NonClosingConnection:
            def __init__(self, connection):
                self.connection = connection

            def cursor(self):
                return self.connection.cursor()

            def close(self):
                return None

            def __getattr__(self, name):
                return getattr(self.connection, name)

        self.route_connection = NonClosingConnection(self.connection)
        self.namespace = {
            **helpers,
            "request": SimpleNamespace(form={}),
            "verify_csrf": lambda: None,
            "get_db_connection": lambda: self.route_connection,
            "get_cursor": lambda connection: connection.cursor(),
            "_referenze_tables_exist": lambda cursor: True,
            "_referenza_decrypt_contact": (
                lambda row, **kwargs: {
                    **dict(row),
                    "referente_nome": "Mario Rossi",
                }
            ),
            "_schede_profilo_begin": (
                lambda cursor: cursor.execute("BEGIN IMMEDIATE")
            ),
            "_schede_profilo_commit": lambda cursor: cursor.execute("COMMIT"),
            "_schede_profilo_rollback": (
                lambda cursor: cursor.execute("ROLLBACK")
            ),
            "app": SimpleNamespace(config={"IS_POSTGRES": False}),
            "sql": lambda query: query,
            "g": SimpleNamespace(utente={"id": 99}),
            "_referenza_evento": event,
            "invalidate_admin_counters": (
                lambda: self.invalidations.append(True)
            ),
            "_referenze_categoria_label": (
                lambda slug: {"babysitter": "Babysitter"}.get(slug, slug)
            ),
            "normalize_language": normalize_language,
            "translate": translate,
            "translate_source": translate_source,
            "_crea_notifica": (
                lambda *args, **kwargs: self.notifications.append((args, kwargs))
            ),
            "emit_update_notifications": lambda user_id: None,
            "log_exception_safe": lambda *args, **kwargs: None,
            "flash": lambda message, category: self.flashes.append(
                (message, category)
            ),
            "url_for": lambda endpoint, **kwargs: f"/{endpoint}",
            "redirect": lambda location: location,
        }
        exec(
            compile(
                ast.Module(body=[function], type_ignores=[]),
                "app.py",
                "exec",
            ),
            self.namespace,
        )

    def tearDown(self):
        self.connection.close()

    def submit(self, **changes):
        form = {
            "versione": "2",
            "stato_verifica": "verificata",
            "metodo_verifica": "telefono",
            "nota_admin": "Contatto concluso",
            "nota_pubblica": "Rapporto confermato dal referente.",
        }
        form.update(changes)
        self.namespace["request"].form = form
        return self.namespace["admin_referenza_verifica"](10)

    def test_success_is_atomic_audited_and_notified(self):
        result = self.submit()
        row = self.connection.execute(
            "SELECT * FROM referenze WHERE id = 10"
        ).fetchone()
        event = self.connection.execute(
            "SELECT * FROM referenze_eventi WHERE referenza_id = 10"
        ).fetchone()

        self.assertEqual(result, "/admin_referenze")
        self.assertEqual(row["stato_verifica"], "verificata")
        self.assertEqual(row["versione"], 3)
        self.assertEqual(row["verificata_da_admin_id"], 99)
        self.assertEqual(row["metodo_verifica"], "telefono")
        self.assertIsNotNone(row["verificata_at"])
        self.assertEqual(event["tipo_evento"], "verifica_admin_registrata")
        self.assertEqual(event["attore_utente_id"], 99)
        self.assertEqual(len(self.invalidations), 1)
        self.assertEqual(self.notifications[0][0][0], 7)

    def test_notification_failure_after_commit_still_redirects_with_success(self):
        def fail_notification(*args, **kwargs):
            raise RuntimeError("notification backend unavailable")

        self.namespace["_crea_notifica"] = fail_notification
        result = self.submit()

        row = self.connection.execute(
            "SELECT stato_verifica, versione FROM referenze WHERE id = 10"
        ).fetchone()
        self.assertEqual(result, "/admin_referenze")
        self.assertEqual(tuple(row), ("verificata", 3))
        self.assertIn(
            ("Esito della referenza registrato.", "success"),
            self.flashes,
        )

    def test_admin_can_approve_publication_independently(self):
        self.connection.execute("""
            UPDATE referenze
            SET autorizza_pubblicazione = 1
            WHERE id = 10
        """)
        self.connection.commit()

        self.submit(pubblicazione_approvata_admin="1")
        row = self.connection.execute("""
            SELECT pubblicazione_approvata_admin,
                   pubblicazione_approvata_at,
                   pubblicazione_approvata_da_admin_id
            FROM referenze
            WHERE id = 10
        """).fetchone()
        self.assertEqual(row["pubblicazione_approvata_admin"], 1)
        self.assertIsNotNone(row["pubblicazione_approvata_at"])
        self.assertEqual(row["pubblicazione_approvata_da_admin_id"], 99)

    def test_stale_version_does_not_write_event_or_notify(self):
        self.namespace["request"].form = {
            "versione": "1",
            "stato_verifica": "verificata",
            "metodo_verifica": "telefono",
            "nota_admin": "",
            "nota_pubblica": "",
        }
        self.namespace["admin_referenza_verifica"](10)

        row = self.connection.execute(
            "SELECT stato_verifica, versione FROM referenze WHERE id = 10"
        ).fetchone()
        events = self.connection.execute(
            "SELECT COUNT(*) FROM referenze_eventi"
        ).fetchone()[0]
        self.assertEqual(tuple(row), ("in_coda", 2))
        self.assertEqual(events, 0)
        self.assertEqual(self.notifications, [])
        self.assertEqual(self.invalidations, [])
        self.assertTrue(any(category == "warning" for _, category in self.flashes))

    def test_without_contact_consent_only_non_verifiable_is_accepted(self):
        self.connection.execute("""
            UPDATE referenze
            SET autorizza_contatto_verifica = 0
            WHERE id = 10
        """)
        self.connection.commit()

        self.submit()
        unchanged = self.connection.execute(
            "SELECT stato_verifica, versione FROM referenze WHERE id = 10"
        ).fetchone()
        self.assertEqual(tuple(unchanged), ("in_coda", 2))

        self.submit(
            stato_verifica="non_verificabile",
            metodo_verifica="",
            nota_admin="Il referente non ha autorizzato il contatto.",
            nota_pubblica="",
        )
        updated = self.connection.execute(
            "SELECT stato_verifica, metodo_verifica, versione "
            "FROM referenze WHERE id = 10"
        ).fetchone()
        self.assertEqual(
            tuple(updated),
            ("non_verificabile", "nessuno", 3),
        )
        self.assertEqual(
            self.notifications,
            [],
            "L'esito interno non verificabile non deve essere mostrato "
            "all'utente tramite notifica.",
        )


class ReferenzeAdminRouteContractTest(unittest.TestCase):
    def test_routes_keep_security_and_admin_side_effects(self):
        self.assertIn('@app.route("/admin/referenze")', APP_SOURCE)
        self.assertIn(
            '@app.route("/admin/referenze/<int:referenza_id>/verifica", '
            'methods=["POST"])',
            APP_SOURCE,
        )
        post_source = ast.get_source_segment(
            APP_SOURCE,
            next(
                node for node in APP_TREE.body
                if isinstance(node, ast.FunctionDef)
                and node.name == "admin_referenza_verifica"
            ),
        )
        list_source = ast.get_source_segment(
            APP_SOURCE,
            next(
                node for node in APP_TREE.body
                if isinstance(node, ast.FunctionDef)
                and node.name == "admin_referenze"
            ),
        )
        self.assertIn("include_invitation_email=False", list_source)
        self.assertIn("include_invitation_email=False", post_source)
        self.assertIn("c.telefono_cifrato IS NOT NULL", post_source)
        for marker in (
            "verify_csrf()",
            "AND versione = ?",
            "_referenza_evento(",
            "invalidate_admin_counters()",
            "_crea_notifica(",
            "emit_update_notifications(owner_id)",
            'url_for("dashboard") + "#referenze"',
        ):
            self.assertIn(marker, post_source)


if __name__ == "__main__":
    unittest.main()
