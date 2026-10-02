import pathlib
import shutil
import subprocess
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SEARCH_TEMPLATE = ROOT / "templates" / "cerca.html"
LISTING_TEMPLATE = ROOT / "templates" / "annuncio_pubblico.html"
RETURN_SCRIPT = ROOT / "static" / "js" / "cerca-return-state.js"
SOCKET_SCRIPT = ROOT / "static" / "js" / "socket_global.js"


class CercaReturnStateUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.search_template = SEARCH_TEMPLATE.read_text(encoding="utf-8")
        cls.listing_template = LISTING_TEMPLATE.read_text(encoding="utf-8")
        cls.return_script = RETURN_SCRIPT.read_text(encoding="utf-8")
        cls.socket_script = SOCKET_SCRIPT.read_text(encoding="utf-8")

    def test_all_search_cards_expose_stable_return_identity(self):
        self.assertIn("js/cerca-return-state.js", self.search_template)
        self.assertEqual(
            self.search_template.count('data-annuncio-id="{{ a[\'id\'] }}"'),
            3,
        )
        for kind in ("vetrina-mobile", "vetrina-desktop", "risultati"):
            self.assertIn(f'data-cerca-card-kind="{kind}"', self.search_template)

    def test_bfcache_is_not_forcibly_reloaded_on_search(self):
        guard = 'document.body.classList.contains("page-cerca")'
        reload_call = "window.location.reload();"
        self.assertIn(guard, self.socket_script)
        self.assertLess(self.socket_script.index(guard), self.socket_script.index(reload_call))
        self.assertIn('event.persisted === true', self.socket_script)
        self.assertIn('disposePageSocket(event && event.persisted', self.socket_script)
        self.assertIn(
            'if (!(document.body && document.body.classList.contains("page-cerca")))',
            self.socket_script,
        )

    def test_listing_back_button_prefers_history_for_a_real_search_origin(self):
        self.assertIn('const cercaPendingKey = "lc_cerca_pending_return_v1"', self.listing_template)
        self.assertIn("document.referrer", self.listing_template)
        self.assertIn("window.history.back();", self.listing_template)

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_script_saves_and_restores_exact_search_scroll_and_panel(self):
        node_program = textwrap.dedent(
            r"""
            const fs = require("fs");
            const vm = require("vm");
            const assert = require("assert");

            class Storage {
              constructor() { this.data = new Map(); }
              getItem(key) { return this.data.has(key) ? this.data.get(key) : null; }
              setItem(key, value) { this.data.set(key, String(value)); }
              removeItem(key) { this.data.delete(key); }
            }

            const windowListeners = {};
            const documentListeners = {};
            const panelClasses = new Set(["hidden"]);
            const filterPanel = {
              classList: {
                contains: (value) => panelClasses.has(value),
                remove: (value) => panelClasses.delete(value),
              },
            };
            const filterToggle = {
              attrs: {},
              setAttribute(name, value) { this.attrs[name] = value; },
            };
            const horizontal = { scrollLeft: 85 };
            const absoluteCardTop = 820;
            const card = {
              dataset: {
                url: "/annuncio/47",
                annuncioId: "47",
                cercaCardKind: "risultati",
              },
              getBoundingClientRect() {
                return { top: absoluteCardTop - window.scrollY };
              },
            };

            global.CSS = { escape: (value) => String(value) };
            global.window = {
              location: {
                pathname: "/cerca",
                search: "?categoria=babysitter&zona=Milano",
                href: "https://example.test/cerca?categoria=babysitter&zona=Milano",
                origin: "https://example.test",
              },
              performance: { getEntriesByType() { return [{ type: "back_forward" }]; } },
              history: {
                state: null,
                replaceState(state) { this.state = state; },
              },
              sessionStorage: new Storage(),
              scrollY: 640,
              scrollTo(x, y) { this.scrollY = y; },
              requestAnimationFrame(callback) { callback(); },
              addEventListener(name, callback) { windowListeners[name] = callback; },
            };
            global.document = {
              addEventListener(name, callback) { documentListeners[name] = callback; },
              getElementById(id) {
                if (id === "filtri-container") return filterPanel;
                if (id === "toggle-filtri") return filterToggle;
                return null;
              },
              querySelectorAll(selector) {
                if (selector === ".vetrina-mobile-scroll") return [horizontal];
                return [];
              },
              querySelector(selector) {
                return selector.includes('data-annuncio-id="47"') &&
                  selector.includes('data-cerca-card-kind="risultati"')
                  ? card
                  : null;
              },
            };

            vm.runInThisContext(fs.readFileSync(process.argv[1], "utf8"));

            panelClasses.delete("hidden");
            documentListeners.click({
              target: {
                closest(selector) {
                  if (selector === ".js-open-annuncio[data-url]") return card;
                  return null;
                },
              },
            });

            const url = "/cerca?categoria=babysitter&zona=Milano";
            const saved = JSON.parse(window.sessionStorage.getItem(
              `lc_cerca_return_state_v1:${url}`
            ));
            assert.equal(saved.scrollY, 640);
            assert.equal(saved.annuncioId, "47");
            assert.equal(saved.cardKind, "risultati");
            assert.equal(saved.filtersOpen, true);
            assert.equal(saved.horizontalScrolls[0].left, 85);

            window.scrollY = 0;
            horizontal.scrollLeft = 0;
            panelClasses.add("hidden");
            windowListeners.pageshow({ persisted: true });

            assert.equal(window.scrollY, 640);
            assert.equal(horizontal.scrollLeft, 85);
            assert.equal(panelClasses.has("hidden"), false);
            assert.equal(filterToggle.attrs["aria-expanded"], "true");
            assert.equal(window.sessionStorage.getItem("lc_cerca_pending_return_v1"), null);
            """
        )
        completed = subprocess.run(
            [shutil.which("node"), "-e", node_program, str(RETURN_SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
