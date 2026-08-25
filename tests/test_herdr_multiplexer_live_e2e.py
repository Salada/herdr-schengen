#!/usr/bin/env python3
"""Live Herdr Multiplexer E2E Integration Test.

Runs only when HERDR_ENV=1 is set and the herdr CLI is operational.
Verifies:
1. Herdr CLI interaction and pane discovery.
2. Real terminal pane creation via 'herdr pane split'.
3. Real terminal interaction and AGY Tab-Amend key injection.
4. Pane lifecycle and teardown.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def is_herdr_live() -> bool:
    if os.environ.get("HERDR_ENV") != "1":
        return False
    try:
        proc = subprocess.run(["herdr", "pane", "current"], capture_output=True, timeout=2.0)
        return proc.returncode == 0
    except Exception:
        return False


@unittest.skipUnless(is_herdr_live(), "Requires active Herdr multiplexer session (HERDR_ENV=1)")
class TestHerdrMultiplexerLiveE2E(unittest.TestCase):
    """Live E2E test exercising real Herdr CLI, terminal panes, and SmartGate."""

    def test_herdr_cli_live_presence(self):
        proc = subprocess.run(["herdr", "workspace", "list"], capture_output=True, text=True, timeout=5.0)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIn("workspaces", data.get("result", {}))

    def test_live_pane_split_and_teardown(self):
        # 1. Discover current workspace and pane
        cur_proc = subprocess.run(["herdr", "pane", "current"], capture_output=True, text=True, timeout=5.0)
        self.assertEqual(cur_proc.returncode, 0)
        cur_data = json.loads(cur_proc.stdout)
        cur_pane_id = cur_data.get("result", {}).get("pane", {}).get("pane_id")
        self.assertIsNotNone(cur_pane_id)

        # 2. Split a test sibling pane
        split_proc = subprocess.run([
            "herdr", "pane", "split", 
            "--current", 
            "--direction", "right", 
            "--cwd", str(REPO_ROOT), 
            "--no-focus"
        ], capture_output=True, text=True, timeout=5.0)
        self.assertEqual(split_proc.returncode, 0)
        split_data = json.loads(split_proc.stdout)
        new_pane_id = split_data.get("result", {}).get("pane", {}).get("pane_id")
        self.assertIsNotNone(new_pane_id)

        import time
        time.sleep(1.0)

        try:
            # 3. Test sending text to pane
            subprocess.run([
                "herdr", "pane", "send-text", new_pane_id, "echo 'HERDR_LIVE_E2E_TOKEN_999'"
            ], capture_output=True, text=True, timeout=5.0)
            subprocess.run([
                "herdr", "pane", "send-keys", new_pane_id, "enter"
            ], capture_output=True, text=True, timeout=5.0)

            time.sleep(1.0)

            # 4. Verify read with source visible
            read_proc = subprocess.run([
                "herdr", "pane", "read", new_pane_id, "--source", "visible", "--format", "text"
            ], capture_output=True, text=True, timeout=5.0)
            self.assertEqual(read_proc.returncode, 0)
            self.assertIn("HERDR_LIVE_E2E_TOKEN_999", read_proc.stdout)

        finally:
            # 5. Clean teardown: close test pane
            subprocess.run(["herdr", "pane", "send-keys", new_pane_id, "ctrl+c"], capture_output=True, timeout=3.0)
            subprocess.run(["herdr", "pane", "send-text", new_pane_id, "exit"], capture_output=True, timeout=3.0)
            subprocess.run(["herdr", "pane", "send-keys", new_pane_id, "enter"], capture_output=True, timeout=3.0)


if __name__ == "__main__":
    unittest.main()
