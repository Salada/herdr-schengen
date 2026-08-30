"""Stale escalation auto-eviction tests (issue #33).

Verifies `_should_evict_stale_escalation`: a cached UNSAFE escalation whose
agent was `blocked` at cache time is auto-evicted once the agent transitions to
a non-blocked state (pane-direct adjudication), while everything else stays.
"""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from cmd.schengen_watcher import _should_evict_stale_escalation


class TestStaleEscalationEviction(unittest.TestCase):
    def test_blocked_to_working_evicts(self):
        self.assertTrue(_should_evict_stale_escalation({"is_safe": False, "status": "blocked"}, "working"))

    def test_blocked_to_idle_evicts(self):
        self.assertTrue(_should_evict_stale_escalation({"is_safe": False, "status": "blocked"}, "idle"))

    def test_blocked_to_done_evicts(self):
        self.assertTrue(_should_evict_stale_escalation({"is_safe": False, "status": "blocked"}, "done"))

    def test_safe_cached_never_evicts(self):
        # Auto-approved commands are not escalations -> never evicted here.
        self.assertFalse(_should_evict_stale_escalation({"is_safe": True, "status": "blocked"}, "working"))

    def test_still_blocked_does_not_evict(self):
        self.assertFalse(_should_evict_stale_escalation({"is_safe": False, "status": "blocked"}, "blocked"))

    def test_unknown_status_does_not_evict(self):
        self.assertFalse(_should_evict_stale_escalation({"is_safe": False, "status": "blocked"}, "unknown"))

    def test_was_not_blocked_does_not_evict(self):
        self.assertFalse(_should_evict_stale_escalation({"is_safe": False, "status": "working"}, "idle"))

    def test_no_cached_entry_does_not_evict(self):
        self.assertFalse(_should_evict_stale_escalation(None, "working"))


if __name__ == "__main__":
    unittest.main()
