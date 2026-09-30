import ast
import unittest
from urllib.parse import parse_qs, urlparse
from pathlib import Path

from flask import Flask, flash, g, redirect, request, url_for


ROOT = Path(__file__).resolve().parents[1]


def load_login_required():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    function = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "login_required"
    )
    namespace = {
        "flash": flash,
        "g": g,
        "redirect": redirect,
        "request": request,
        "url_for": url_for,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "app.py", "exec"), namespace)
    return namespace["login_required"]


class LoginNextRedirectTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY="test-secret")

        @self.app.route("/login", endpoint="login")
        def login_page():
            return "login"

    def test_availability_deep_link_survives_login_redirect(self):
        login_required = load_login_required()
        protected = login_required(lambda: "ok")
        destination = (
            "/utente/dashboard?disponibilita=riconferma"
            "&categoria=babysitter"
        )

        with self.app.test_request_context(destination):
            g.utente = None
            response = protected()

        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response.location)
        self.assertEqual(parsed.path, "/login")
        self.assertEqual(parse_qs(parsed.query).get("next"), [destination])


if __name__ == "__main__":
    unittest.main()
