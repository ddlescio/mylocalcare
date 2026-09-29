import shutil
import subprocess
import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
PRIVATE_PARTIAL = TEMPLATES / "partials" / "referenze_dialog.html"
PUBLIC_PARTIAL = TEMPLATES / "partials" / "referenze_pubbliche.html"
PUBLIC_INFO_TAB = TEMPLATES / "partials" / "tab_info_pubblico.html"
DASHBOARD = TEMPLATES / "dashboard.html"
RESPONSE_PAGE = TEMPLATES / "referenza_risposta.html"
RESULT_PAGE = TEMPLATES / "referenza_risposta_esito.html"
PRIVACY_PAGE = TEMPLATES / "privacy.html"
TERMS_PAGE = TEMPLATES / "termini.html"
SCRIPT = ROOT / "static" / "js" / "referenze.js"
STYLES = ROOT / "static" / "css" / "referenze.css"


class ReferenzeUiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_source = PRIVATE_PARTIAL.read_text(encoding="utf-8")
        cls.public_source = PUBLIC_PARTIAL.read_text(encoding="utf-8")
        cls.public_info_source = PUBLIC_INFO_TAB.read_text(encoding="utf-8")
        cls.dashboard_source = DASHBOARD.read_text(encoding="utf-8")
        cls.response_source = RESPONSE_PAGE.read_text(encoding="utf-8")
        cls.result_source = RESULT_PAGE.read_text(encoding="utf-8")
        cls.privacy_source = PRIVACY_PAGE.read_text(encoding="utf-8")
        cls.terms_source = TERMS_PAGE.read_text(encoding="utf-8")
        cls.script_source = SCRIPT.read_text(encoding="utf-8")
        cls.style_source = STYLES.read_text(encoding="utf-8")

        cls.environment = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            autoescape=select_autoescape(("html",)),
        )
        cls.environment.filters["fmt_it_date"] = lambda value: f"date:{value}"
        cls.environment.globals["tr"] = (
            lambda key, **kwargs: str(key).format(**kwargs)
        )
        cls.environment.globals["tr_text"] = lambda value: value or ""

    def test_templates_parse(self):
        for source in (
            self.private_source,
            self.public_source,
            self.public_info_source,
            self.dashboard_source,
            self.response_source,
            self.result_source,
            self.privacy_source,
            self.terms_source,
        ):
            self.environment.parse(source)

    def test_external_response_pages_link_to_registered_home_endpoint(self):
        for source in (self.response_source, self.result_source):
            self.assertIn("url_for('home')", source)
            self.assertNotIn("url_for('landing')", source)

    def test_references_live_in_feedback_tab_not_info(self):
        self.assertIn(
            "{% include 'partials/referenze_pubbliche.html' %}",
            self.dashboard_source,
        )
        self.assertIn("{% include 'partials/referenze_dialog.html' %}", self.dashboard_source)
        self.assertNotIn("referenze_pubbliche.html", self.public_info_source)
        self.assertNotIn("referenze_dialog.html", self.public_info_source)
        self.assertIn('id="reference-manager" class="reference-manager"', self.private_source)
        self.assertNotIn('id="reference-manager-dialog"', self.private_source)

    def test_feedback_counts_and_deep_link_contract(self):
        self.assertIn("('annunci', tr('profile.announcements'))", self.dashboard_source)
        self.assertLess(self.dashboard_source.index("('info', tr('profile.info'))"), self.dashboard_source.index("('recensioni', tr('profile.reviews'))"))
        self.assertLess(self.dashboard_source.index("('recensioni', tr('profile.reviews'))"), self.dashboard_source.index("('foto', tr('profile.photos'))"))
        self.assertIn(
            "feedback_review_rows = recensioni_ricevute|default([], true)",
            self.dashboard_source,
        )
        self.assertIn(
            "feedback_references = referenze_pubbliche|default([], true)",
            self.dashboard_source,
        )
        self.assertIn("feedback_total_count = feedback_reviews_count + feedback_references_count", self.dashboard_source)
        self.assertIn(
            "key == 'recensioni' and feedback_total_count > 0",
            self.dashboard_source,
        )
        self.assertIn(
            '<span class="profile-tab-count" aria-hidden="true">{{ feedback_total_count }}</span>',
            self.dashboard_source,
        )
        self.assertIn("feedback_received_count + (feedback_written_rows|length)", self.dashboard_source)
        self.assertIn("referenza.get('stato_risposta') == 'risposta_ricevuta'", self.dashboard_source)
        self.assertIn("referenze_pubbliche|default([], true)", self.dashboard_source)
        self.assertIn('data-feedback-jump="references"', self.dashboard_source)
        self.assertIn('data-feedback-section="references"', self.dashboard_source)
        self.assertIn('window.addEventListener("hashchange"', self.dashboard_source)
        self.assertIn('window.addEventListener("profile:open-references"', self.dashboard_source)

    def test_legal_pages_explain_reference_privacy_and_badge_scope(self):
        for marker in (
            "Inviti e referenze",
            "cifratura applicativa",
            "Nome, indirizzo email, numero di telefono, messaggio di invito e altri recapiti del referente restano riservati",
            "può scegliere volontariamente di indicare un nome",
            "non aggiunge automaticamente al contenuto pubblico il nome",
            "con un’unica scelta facoltativa",
            "Se non desidera condividere un commento, può semplicemente non compilarlo",
            "nessuna referenza viene resa pubblica automaticamente",
            "MyLocalCare deve prima approvarne la pubblicazione",
            "può scegliere se mostrarla o nasconderla",
            "non equivale a un controllo della referenza",
            "Referenza ricevuta",
            "Controllata da MyLocalCare",
            "non dimostra né garantisce veridicità dei fatti",
            "scade dopo 14 giorni",
            "30 giorni dopo la scadenza del collegamento",
            "entro 44 giorni dall’invio",
            "non più di 90 giorni",
            "indicare facoltativamente il proprio numero di telefono",
            "specifico consenso, svolgere un riscontro amministrativo telefonico",
            "non come canale proposto per il riscontro della referenza",
            "l’eventuale numero di telefono autorizzato",
            "le scelte di consenso e le registrazioni essenziali",
        ):
            self.assertIn(marker, self.privacy_source)

        for marker in (
            ">5-ter. Referenze<",
            "rapporto effettivo",
            "esperienza diretta",
            "può scegliere di indicare un nome",
            "non aggiunge automaticamente al contenuto pubblico il nome",
            "quando il referente autorizza la pubblicazione della scheda anonima",
            "approvazione finale di MyLocalCare",
            "può scegliere se mostrarla o nasconderla",
            "non costituisce conferma dei fatti, certificazione o garanzia",
            "Referenza ricevuta",
            "Controllata da MyLocalCare",
            "ha successivamente contattato il referente",
            "Neppure tale controllo significa che MyLocalCare abbia accertato o garantisca veridicità dei fatti",
        ):
            self.assertIn(marker, self.terms_source)

    def test_private_manager_uses_domain_endpoints_and_minimal_contact_data(self):
        rendered = self.environment.get_template(
            "partials/referenze_dialog.html"
        ).render(
            referenze_private=[
                {
                    "id": 9,
                    "referente_nome": "Referente test",
                    "categoria_label": "Babysitter",
                    "stato_risposta": "inviata",
                    "stato_verifica": "non_verificata",
                }
            ],
            categorie_referenze=[{"slug": "babysitter", "label": "Babysitter"}],
            csrf_token=lambda: "csrf-test",
            url_for=lambda endpoint, **kwargs: (
                f"/static/{kwargs['filename']}"
                if endpoint == "static"
                else f"/{endpoint}/{kwargs.get('referenza_id', '')}".rstrip("/")
            ),
        )

        self.assertIn('action="/api_referenze_crea"', rendered)
        self.assertIn('data-no-global-loader', rendered)
        self.assertIn('data-endpoint="/api_referenza_reinvia/9"', rendered)
        self.assertIn('data-endpoint="/api_referenza_revoca/9"', rendered)
        self.assertIn("reference.send_new_link", rendered)
        self.assertIn('name="referente_email"', rendered)
        self.assertNotIn('name="referente_telefono"', rendered)
        self.assertIn(
            'name="conferma_condivisione_recapito" value="1" required',
            rendered,
        )
        self.assertIn('name="anno_inizio"', rendered)
        self.assertIn('name="anno_fine"', rendered)
        self.assertIn('name="durata_fascia"', rendered)

    def test_verified_reference_is_managed_outside_sent_requests(self):
        rendered = self.environment.get_template(
            "partials/referenze_dialog.html"
        ).render(
            referenze_private=[
                {
                    "id": 21,
                    "referente_nome": "Referente ricevuto",
                    "categoria_label": "Babysitter",
                    "stato_risposta": "risposta_ricevuta",
                    "stato_verifica": "verificata",
                    "stato": "verificata",
                    "sezione_privata": "ricevuta",
                    "versione": 4,
                },
                {
                    "id": 22,
                    "referente_nome": "Referente invitato",
                    "categoria_label": "Caregiver",
                    "stato_risposta": "in_attesa",
                    "stato_verifica": "non_esaminata",
                    "stato": "inviata",
                    "sezione_privata": "richiesta",
                },
            ],
            categorie_referenze=[],
            csrf_token=lambda: "csrf-test",
            url_for=lambda endpoint, **kwargs: (
                f"/static/{kwargs['filename']}"
                if endpoint == "static"
                else f"/{endpoint}/{kwargs.get('referenza_id', '')}".rstrip("/")
            ),
        )

        received = rendered.split(
            'id="reference-list-received-title"', 1
        )[1].split('id="reference-list-requests-title"', 1)[0]
        requests = rendered.split(
            'id="reference-list-requests-title"', 1
        )[1]
        self.assertIn('data-reference-id="21"', received)
        self.assertNotIn('data-reference-id="22"', received)
        self.assertIn('data-reference-id="22"', requests)
        self.assertNotIn('data-reference-id="21"', requests)
        self.assertIn("reference.received.title", rendered)
        self.assertIn("reference.requests.title", rendered)
        self.assertIn("reference.delete_reference", received)
        self.assertIn('data-reference-delete-kind="reference"', received)
        self.assertIn('data-version="4"', received)
        self.assertNotIn("reference.delete_reference", requests)

    def test_delete_copy_distinguishes_reference_from_request(self):
        self.assertIn(
            'button.dataset.referenceDeleteKind === "reference"',
            self.script_source,
        )
        self.assertIn(
            "Eliminare definitivamente questa referenza?",
            self.script_source,
        )
        self.assertIn(
            "Eliminare definitivamente questa richiesta?",
            self.script_source,
        )
        self.assertIn(
            'versione: Number.parseInt(button.dataset.version || "0", 10)',
            self.script_source,
        )

    def test_private_manager_surfaces_delivery_failure_and_can_revoke_completed(self):
        self.assertIn("reference.status.email_failed", self.private_source)
        self.assertIn("reference.status.email_failed_help", self.private_source)
        self.assertIn("'errore_invio'", self.private_source)
        self.assertIn("{% if stato == 'revocata' %}", self.private_source)
        self.assertIn("data-reference-restore", self.private_source)
        self.assertIn("data-reference-delete", self.private_source)
        self.assertIn("api_referenza_ripristina", self.private_source)
        self.assertIn("api_referenza_elimina", self.private_source)
        self.assertNotIn(
            "{% if stato in ['inviata', 'aperta', 'scaduta'] %}",
            self.private_source,
        )

    def test_revoked_request_can_be_restored_or_deleted(self):
        rendered = self.environment.get_template(
            "partials/referenze_dialog.html"
        ).render(
            referenze_private=[{
                "id": 12,
                "referente_nome": "Referente test",
                "categoria_label": "Babysitter",
                "stato_risposta": "revocata",
                "stato_verifica": "revocata",
                "stato": "revocata",
            }],
            categorie_referenze=[{"slug": "babysitter", "label": "Babysitter"}],
            csrf_token=lambda: "csrf-test",
            url_for=lambda endpoint, **kwargs: (
                f"/static/{kwargs['filename']}"
                if endpoint == "static"
                else f"/{endpoint}/{kwargs.get('referenza_id', '')}".rstrip("/")
            ),
        )

        self.assertIn('data-endpoint="/api_referenza_ripristina/12"', rendered)
        self.assertIn('data-endpoint="/api_referenza_elimina/12"', rendered)
        self.assertNotIn('data-endpoint="/api_referenza_reinvia/12"', rendered)
        self.assertNotIn('data-endpoint="/api_referenza_revoca/12"', rendered)

    def test_user_without_offered_listing_gets_explanation_and_create_link(self):
        rendered = self.environment.get_template(
            "partials/referenze_dialog.html"
        ).render(
            referenze_private=[],
            categorie_referenze=[],
            csrf_token=lambda: "csrf-test",
            url_for=lambda endpoint, **kwargs: (
                f"/static/{kwargs['filename']}"
                if endpoint == "static"
                else f"/{endpoint}"
            ),
        )

        self.assertIn("reference.no_listing.title", rendered)
        self.assertIn("reference.no_listing.body", rendered)
        self.assertIn("reference.no_listing.action", rendered)
        self.assertIn('href="/nuovo_annuncio"', rendered)
        self.assertNotIn('id="reference-invite-form"', rendered)

    def test_owner_sees_full_details_and_controls_approved_visibility(self):
        for marker in (
            "reference.details.open",
            "reference.details.duration",
            "reference.details.comment",
            "referenza.get('testo_referente')",
            "reference.details.public_card",
            "reference.details.public_comment",
            "reference.waiting_admin_approval",
            "reference.hidden_by_you",
            "data-reference-visibility",
            "api_referenza_visibilita",
            "data-version=",
        ):
            self.assertIn(marker, self.private_source)

        for marker in (
            "postReferenceVisibility",
            "visibile_profilo",
            "versione: version",
            "[data-reference-visibility]",
        ):
            self.assertIn(marker, self.script_source)

    def test_duration_enum_matches_domain(self):
        expected = {
            "meno_3_mesi",
            "3_6_mesi",
            "6_12_mesi",
            "1_2_anni",
            "oltre_2_anni",
        }
        for value in expected:
            self.assertIn(f'value="{value}"', self.private_source)
            self.assertIn(f'value="{value}"', self.response_source)

        for legacy in ("meno_1_mese", "1_3_mesi", "oltre_1_anno", "occasionale"):
            self.assertNotIn(f'value="{legacy}"', self.private_source)
            self.assertNotIn(f'value="{legacy}"', self.response_source)

    def test_response_form_has_exactly_three_clear_consents(self):
        self.assertIn("action=\"{{ url_for('referenza_rispondi') }}\"", self.response_source)
        self.assertNotIn('name="token_form"', self.response_source)
        for name in (
            "categoria_slug",
            "tipo_rapporto",
            "anno_inizio",
            "anno_fine",
            "durata_fascia",
            "testo_referente",
            "consenso_contatto",
            "referente_telefono",
        ):
            self.assertIn(f'name="{name}"', self.response_source)
        self.assertIn('type="tel"', self.response_source)
        self.assertIn('inputmode="tel"', self.response_source)
        self.assertIn('autocomplete="tel"', self.response_source)
        self.assertIn('maxlength="40"', self.response_source)
        self.assertIn("reference.response.phone_help", self.response_source)
        self.assertIn("data-reference-contact-consent", self.response_source)
        self.assertIn("data-reference-contact-details", self.response_source)
        self.assertIn("consent.required = hasPhone;", self.script_source)
        self.assertIn("phone.required = consent.checked;", self.script_source)
        self.assertNotIn("details.hidden =", self.script_source)
        self.assertNotIn("phone.disabled = !contactAllowed", self.script_source)
        self.assertIn("phone.disabled = cannotConfirm;", self.script_source)
        self.assertIn('name="autorizza_pubblicazione"', self.response_source)
        publication_input = self.response_source.split(
            'name="autorizza_pubblicazione"', 1
        )[1].split(">", 1)[0]
        self.assertNotIn("required", publication_input)
        self.assertIn("reference.response.public_consent", self.response_source)
        self.assertNotIn('name="autorizza_testo_pubblico"', self.response_source)
        self.assertEqual(self.response_source.count('type="checkbox"'), 3)
        self.assertEqual(
            self.response_source.count("data-reference-consent-option"),
            3,
        )
        self.assertIn("data-reference-accept-all", self.response_source)
        self.assertIn("reference.response.accept_all", self.response_source)
        self.assertIn("data-reference-incomplete-confirm", self.response_source)
        self.assertEqual(self.response_source.count('name="csrf_token"'), 1)

    def test_response_categories_come_from_the_current_service_catalog(self):
        self.assertIn(
            "{% for voce in categorie_referenze|default([], true) %}",
            self.response_source,
        )
        self.assertNotIn('<option value="operatori-benessere"', self.response_source)

    def test_public_partial_exposes_only_public_serializer_fields(self):
        for key in (
            "categoria_slug",
            "categoria_label",
            "tipo_rapporto_label",
            "periodo_label",
            "durata_label",
            "stato_label",
            "testo_referente_pubblico",
            "verificata",
        ):
            self.assertIn(f"referenza.get('{key}')", self.public_source)

        for private_key in (
            "referente_nome",
            "referente_email",
            "referente_telefono",
            "testo_referente')",
        ):
            self.assertNotIn(private_key, self.public_source)

        self.assertIn("reference.public.authorised_info", self.public_source)
        self.assertIn("reference.public.declared_by_referee", self.public_source)
        self.assertIn("reference.public.limited_check", self.public_source)
        self.assertIn("reference.public.disclaimer", self.public_source)
        self.assertNotIn("Rapporto confermato da MyLocalCare", self.public_source)
        self.assertNotIn("Esperienze confermate direttamente", self.public_source)
        self.assertIn('data-reference-public-open=', self.public_source)
        self.assertIn('aria-haspopup="dialog"', self.public_source)

    def test_dialogs_are_mobile_first_and_accessible(self):
        for marker in (
            'aria-labelledby="reference-manager-title"',
            'role="alert"',
            'aria-live="polite"',
        ):
            self.assertIn(marker, self.private_source)

        self.assertIn('role="dialog"', self.public_source)
        self.assertIn('aria-modal="true"', self.public_source)

        for marker in (
            'event.key === "Escape"',
            'event.key !== "Tab"',
            'classList.add("reference-dialog-open")',
            "returnFocusTo.focus",
            "template.content.cloneNode(true)",
        ):
            self.assertIn(marker, self.script_source)

        self.assertIn("max-height: 92vh;", self.style_source)
        self.assertIn("max-height: min(92dvh, 58rem);", self.style_source)
        self.assertIn("@media (min-width: 520px)", self.style_source)
        self.assertIn("min-height: 2.75rem", self.style_source)

    def test_reference_fields_do_not_trigger_ios_focus_zoom(self):
        controls = self.style_source.split(
            ".reference-field input,", 1
        )[1].split("}", 1)[0]
        self.assertIn("font-size: 16px;", controls)

    def test_progressive_enhancement_keeps_real_forms(self):
        self.assertIn('method="post"', self.private_source)
        self.assertIn('method="post"', self.response_source)
        self.assertIn('data-no-global-loader', self.private_source)
        self.assertIn("if (!form || !global.fetch || !global.FormData) return;", self.script_source)
        self.assertIn('credentials: "same-origin"', self.script_source)
        self.assertIn('"X-CSRF-Token": csrfToken()', self.script_source)
        self.assertIn('form.dataset.referenceSubmitting === "1"', self.script_source)
        self.assertIn('delete form.dataset.referenceSubmitting;', self.script_source)

    def test_external_page_is_not_indexed_and_explains_privacy(self):
        self.assertIn('name="robots" content="noindex,nofollow"', self.response_source)
        self.assertIn("reference.response.intro", self.response_source)
        self.assertIn("reference.response.privacy_identity", self.response_source)
        self.assertIn("reference.response.privacy_warning", self.response_source)
        self.assertIn("get_flashed_messages(with_categories=true)", self.response_source)
        self.assertIn('role="alert"', self.response_source)
        self.assertLess(
            self.response_source.index('class="reference-response-privacy"'),
            self.response_source.index('name="consenso_trattamento"'),
        )

    def test_public_comment_follows_single_publication_consent(self):
        self.assertNotIn("const publicTextAllowed = (", self.script_source)
        self.assertNotIn("publicText.disabled", self.script_source)
        self.assertIn("input[name='autorizza_pubblicazione']", self.script_source)
        self.assertIn("function enabledConsentOptions(form)", self.script_source)
        self.assertIn("function acceptAllConsents(form)", self.script_source)
        self.assertIn("global.confirm(message)", self.script_source)

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_javascript_syntax(self):
        result = subprocess.run(
            ["node", "--check", str(SCRIPT)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        marker = "const feedbackButtons = document.querySelectorAll(\"[data-feedback-section]\");"
        marker_position = self.dashboard_source.index(marker)
        script_start = self.dashboard_source.rfind("<script>", 0, marker_position) + len("<script>")
        script_end = self.dashboard_source.index("</script>", marker_position)
        result = subprocess.run(
            ["node", "--check", "-"],
            input=self.dashboard_source[script_start:script_end],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
