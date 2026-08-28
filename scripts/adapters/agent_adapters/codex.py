"""Codex (OpenAI Codex CLI) adapter — approval prompt parsing and key injection.

Codex renders approval requests as a ratatui list-selection modal:

    Would you like to run the following command?
    [Environment: <env>]
    [Reason: <reason>]
    $ <command>                      (bash-highlighted, wrapped)
    › 1. Yes, proceed (y)
      2. No, and tell Codex what to do differently (esc)
    Press enter to confirm or esc to cancel

Default keymap (approval): `y`/Enter approve, `n`/Esc decline, `d` deny,
`Ctrl+C` abort, `Ctrl+A` fullscreen pager.
"""

import re

from adapters.herdr_client import run_cmd

from adapters.agent_adapters.base import AgentAdapter, register


@register
class CodexAdapter(AgentAdapter):
    kind = "codex"

    blocked_markers = (
        "Would you like to run the following command?",
        "Do you want to approve network access",
        "Would you like to send input to terminal",
        "Would you like to grant these permissions?",
        "Would you like to make the following edits?",
        "needs your approval.",
        "Yes, proceed",
        "Press enter to confirm or esc to cancel",
    )

    def parse_permission_request(self, visible_text):
        """Extract the command/action from a Codex approval modal."""
        # Exec (shell): the "$ <command>" body before the "1. Yes" option row.
        m = re.search(r"\$\s+([\s\S]*?)\n\s*[›>]?\s*1\.\s*Yes", visible_text)
        if m:
            cmd = re.sub(r"\s+", " ", m.group(1)).strip()
            if cmd:
                return cmd

        # Network access: Do you want to approve network access to "<host>"?
        m = re.search(r'network access to\s*"([^"]+)"', visible_text)
        if m:
            return f"network_access {m.group(1)}"

        # Write to stdin: Would you like to send input to terminal <id>?
        m = re.search(r"send input to terminal\s+(\d+)", visible_text)
        if m:
            return f"stdin_terminal {m.group(1)}"

        # File edit: Would you like to make the following edits?
        if "Would you like to make the following edits?" in visible_text:
            return "edit_file"

        # Permissions: Would you like to grant these permissions?
        if "Would you like to grant these permissions?" in visible_text:
            return "grant_permissions"

        return None

    def inject_approval(self, pane_id, req_cmd):
        """Approve via 'y' (selection-independent, per Codex default keymap)."""
        print(f"🚀 Auto-approving codex request for {pane_id} (sending 'y')...", flush=True)
        run_cmd(["herdr", "agent", "send-keys", pane_id, "y"])
        return True, "approved (y)"
