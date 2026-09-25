import unittest
import shutil
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]


class DisponibilitaDialogScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        environment = Environment(loader=FileSystemLoader(ROOT / "templates"))
        template = environment.get_template(
            "partials/disponibilita_servizi_dialog.html"
        )
        cls.rendered = template.render(
            pubblico=False,
            tr=lambda key, **values: key,
            csrf_token=lambda: "scope-test-token",
        )

    def test_dialog_exposes_accessible_service_scope_controls(self):
        self.assertIn('name="service-availability-scope"', self.rendered)
        self.assertIn('value="general"', self.rendered)
        self.assertIn('value="category"', self.rendered)
        self.assertIn('id="service-availability-category"', self.rendered)
        self.assertIn("availability.no_offered_categories", self.rendered)

    def test_api_payload_contains_selected_category(self):
        self.assertIn("categoria_slug: categorySlug || null", self.rendered)
        self.assertIn('body: JSON.stringify({', self.rendered)
        self.assertIn("button.dataset.availabilityCategory", self.rendered)

    def test_script_accepts_multiple_and_legacy_api_shapes(self):
        self.assertIn("root.profili", self.rendered)
        self.assertIn("root.disponibilita", self.rendered)
        self.assertIn("profilesByScope", self.rendered)
        self.assertIn(
            'trigger.getAttribute("data-service-availability-category")',
            self.rendered,
        )

    def test_category_labels_are_localized_by_slug(self):
        self.assertIn("const categoryLabels = Object.freeze", self.rendered)
        self.assertIn(
            "availability.category.operatori-benessere",
            self.rendered,
        )
        self.assertIn("categoryLabels[slug]", self.rendered)

    def test_first_save_respects_server_scope_eligibility(self):
        self.assertIn("scope_categoria_disponibile", self.rendered)
        self.assertIn("utente_offre_servizi", self.rendered)
        self.assertIn("scopeCategoryAvailable", self.rendered)
        self.assertIn("userOffersServices", self.rendered)
        self.assertIn("!canSaveSelectedScope()", self.rendered)
        self.assertIn("availability.scope_category_disabled", self.rendered)

    def test_existing_scope_can_be_removed_with_confirmation(self):
        self.assertIn('id="service-availability-delete"', self.rendered)
        self.assertIn('method: "DELETE"', self.rendered)
        self.assertIn("window.confirm(confirmationMessage)", self.rendered)
        self.assertIn("categoria_slug: categorySlug || null", self.rendered)
        self.assertIn(
            "availability.delete_profile_category_fallback",
            self.rendered,
        )

    def test_public_data_warning_and_unavailable_state_are_explicit(self):
        self.assertIn("availability.public_data_notice", self.rendered)
        self.assertIn(
            'id="service-availability-positive-details"',
            self.rendered,
        )
        self.assertIn("section.disabled = busy || unavailable", self.rendered)
        self.assertIn('positiveDetails.classList.toggle("is-suspended"', self.rendered)

    def test_reconfirmation_deep_link_opens_requested_scope_and_cleans_url(self):
        self.assertIn(
            'url.searchParams.get("disponibilita") !== "riconferma"',
            self.rendered,
        )
        self.assertIn(
            'normalizeCategorySlug(url.searchParams.get("categoria"))',
            self.rendered,
        )
        self.assertIn(
            '"data-service-availability-category",',
            self.rendered,
        )
        self.assertIn(
            "loadAvailability(trigger).finally(() => deepLink.clean())",
            self.rendered,
        )
        self.assertIn('url.searchParams.delete("disponibilita")', self.rendered)
        self.assertIn('url.searchParams.delete("categoria")', self.rendered)
        self.assertIn(
            'window.history.replaceState(window.history.state, "", cleanUrl)',
            self.rendered,
        )
        self.assertIn("openAvailabilityFromDeepLink();", self.rendered)

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_rendered_dialog_javascript_has_valid_syntax(self):
        start = self.rendered.index("<script>") + len("<script>")
        end = self.rendered.index("</script>", start)
        script = self.rendered[start:end]
        result = subprocess.run(
            ["node", "--check"],
            input=script,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
