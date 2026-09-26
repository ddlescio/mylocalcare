import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
CHAT_SOURCE = (
    ROOT / "templates" / "chat_conversazione.html"
).read_text(encoding="utf-8")


def function_source(name):
    tree = ast.parse(APP_SOURCE)
    node = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == name
    )
    return ast.get_source_segment(APP_SOURCE, node)


class ChatReadVisibilityTest(unittest.TestCase):
    def test_html_and_polling_routes_do_not_mark_messages_read(self):
        for route_name in (
            "chat_conversazione_view",
            "chat_conversazione_json",
        ):
            with self.subTest(route=route_name):
                route_source = function_source(route_name)
                self.assertNotIn("chat_segna_letti", route_source)
                self.assertNotIn("update_unread_count", route_source)

    def test_active_chat_requires_visibility_and_window_focus(self):
        self.assertIn("function isChatActivelyViewed()", CHAT_SOURCE)
        self.assertIn(
            'document.visibilityState === "visible"',
            CHAT_SOURCE,
        )
        self.assertIn(
            'typeof document.hasFocus !== "function"',
            CHAT_SOURCE,
        )
        self.assertIn("document.hasFocus()", CHAT_SOURCE)

    def test_new_message_checks_focus_before_and_after_delay(self):
        self.assertIn(
            "m.destinatario_id === meId && isChatActivelyViewed()",
            CHAT_SOURCE,
        )
        self.assertIn(
            "isChatActivelyViewed()\n"
            "                && activeSocket",
            CHAT_SOURCE,
        )
        self.assertNotIn(
            'm.destinatario_id === meId '
            '&& document.visibilityState === "visible"',
            CHAT_SOURCE,
        )

    def test_polling_runs_only_while_chat_has_focus(self):
        poll_start = CHAT_SOURCE.index("async function pollNewMessages()")
        poll_end = CHAT_SOURCE.index(
            "function startPollingFallback()",
            poll_start,
        )
        poll_source = CHAT_SOURCE[poll_start:poll_end]
        self.assertIn("if (!isChatActivelyViewed()) return;", poll_source)
        self.assertNotIn(
            'if (document.visibilityState !== "visible") return;',
            poll_source,
        )


if __name__ == "__main__":
    unittest.main()
