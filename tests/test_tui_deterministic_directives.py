"""TUI wiring for deterministic human directives and scoped URL policy."""

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from cmd.schengen_tui import SchengenTUIApp


def bare_app(processing=False):
    app = SchengenTUIApp.__new__(SchengenTUIApp)
    app._processing_chat = processing
    app._judging_escalation_id = None
    app._last_chat_date = None
    app.is_controller = True
    app.leader_pid = None
    app._write = MagicMock()
    app._write_markdown = MagicMock()
    app.update_radar_data = MagicMock()
    app.agent = MagicMock()
    app.agent.send_message = AsyncMock(side_effect=AssertionError("directive must not call the LLM"))
    return app


class TestTuiDeterministicDirective(unittest.TestCase):
    def run_chat(self, app, text):
        asyncio.run(SchengenTUIApp.process_user_chat.__wrapped__(app, text))

    def test_korean_approval_bypasses_busy_llm_and_uses_active_head(self):
        app = bare_app(processing=True)
        active = {"id": 908, "pane_id": "w1D:p1"}
        with patch("cmd.schengen_tui.get_current_command_escalation", return_value=active), patch(
            "cmd.schengen_tui.record_human_opinion"
        ) as opinion, patch(
            "cmd.schengen_tui.execute_tool_call", return_value=json.dumps({"status": "success"})
        ) as execute:
            self.run_chat(app, "승인")
        opinion.assert_called_once_with(908, "승인")
        execute.assert_called_once_with(
            "approve_escalation",
            {"escalation_id": 908, "english_feedback": "승인", "directive": True},
        )
        app.agent.send_message.assert_not_awaited()

    def test_explicit_wrong_id_cannot_mutate_non_head(self):
        app = bare_app()
        with patch("cmd.schengen_tui.get_current_command_escalation", return_value={"id": 910}), patch(
            "cmd.schengen_tui.record_human_opinion"
        ) as opinion, patch("cmd.schengen_tui.execute_tool_call") as execute:
            self.run_chat(app, "/approve 911")
        opinion.assert_not_called()
        execute.assert_not_called()

    def test_question_only_queue_cannot_be_adjudicated(self):
        app = bare_app()
        with patch("cmd.schengen_tui.get_current_command_escalation", return_value=None), patch(
            "cmd.schengen_tui.execute_tool_call"
        ) as execute:
            self.run_chat(app, "진행해")
        execute.assert_not_called()

    def test_allow_url_command_is_explicit_and_does_not_call_llm(self):
        app = bare_app()
        with patch("cmd.schengen_tui.add_url_to_allowlist", return_value="developers.openai.com") as add:
            self.run_chat(app, "/allow-url developers.openai.com official-docs")
        add.assert_called_once_with("developers.openai.com", "official-docs", created_by="human-tui")
        app.agent.send_message.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
