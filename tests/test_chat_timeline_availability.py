import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "static" / "js" / "chat-timeline.js"
CHAT_TEMPLATE = ROOT / "templates" / "chat_conversazione.html"
REQUEST_PARTIAL = (
    ROOT / "templates" / "partials" / "richieste_disponibilita_proprietario.html"
)


class ChatTimelineAvailabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script_source = SCRIPT.read_text(encoding="utf-8")
        cls.chat_source = CHAT_TEMPLATE.read_text(encoding="utf-8")
        cls.partial_source = REQUEST_PARTIAL.read_text(encoding="utf-8")

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_message_request_message_response_are_sorted_by_timestamp(self):
        node_program = r"""
const api = require(process.argv[1]);
const events = [
  { id: "response-41", timestamp: "2026-09-25T09:13:00+02:00" },
  { id: "message-2", timestamp: "2026-09-25T09:12:00+02:00" },
  { id: "request-41", timestamp: "2026-09-25T09:11:00+02:00" },
  { id: "message-1", timestamp: "2026-09-25T09:10:00+02:00" }
];
process.stdout.write(JSON.stringify(
  api.sortTimelineEntries(events).map((event) => event.id)
));
"""
        completed = subprocess.run(
            [shutil.which("node"), "-e", node_program, str(SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            ["message-1", "request-41", "message-2", "response-41"],
            json.loads(completed.stdout),
        )

    def test_timeline_is_wired_for_initial_and_realtime_events(self):
        self.assertIn("js/chat-timeline.js", self.chat_source)
        self.assertIn("data-owner-availability-request", self.partial_source)
        self.assertIn("data-owner-availability-response-event", self.partial_source)
        self.assertIn("data-chat-timeline-at", self.partial_source)
        self.assertIn("localcare:availability-cards-refreshed", self.script_source)
        self.assertIn(
            "localcare:richiesta-disponibilita-risposta",
            self.script_source,
        )

    def test_timeline_keeps_request_and_response_as_structured_cards(self):
        self.assertIn('"[data-owner-availability-request]"', self.script_source)
        self.assertIn(
            '"[data-owner-availability-response-event]"',
            self.script_source,
        )
        self.assertNotIn("data-mid", self.partial_source)

    @unittest.skipUnless(shutil.which("node"), "Node.js non disponibile")
    def test_day_key_uses_local_day_after_timezone_conversion(self):
        node_program = r"""
const api = require(process.argv[1]);
process.stdout.write(JSON.stringify({
  utcNearMidnight: api.dayKey("2026-09-25T22:30:00Z"),
  localWithoutOffset: api.dayKey("2026-09-25 23:30:00")
}));
"""
        completed = subprocess.run(
            [shutil.which("node"), "-e", node_program, str(SCRIPT)],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "TZ": "Europe/Rome"},
        )
        self.assertEqual(
            {
                "utcNearMidnight": "2026-09-26",
                "localWithoutOffset": "2026-09-25",
            },
            json.loads(completed.stdout),
        )


if __name__ == "__main__":
    unittest.main()
