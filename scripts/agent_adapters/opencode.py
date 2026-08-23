"""OpenCode adapter — permission dialog parsing and Q3 fail-safe key injection.

opencode's permission dialog is a horizontal button row
{once:"Allow once", always:"Allow always", reject:"Reject"} rendered on the
alternate-screen Bubble Tea TUI, with 'once' pre-selected on fresh mount
(source-verified: selected = keys[0]). A single `enter` deterministically
selects 'once'; arrows/numbers are NOT supported and MUST NOT be sent.
"""

import re
import time

from agent_adapters.base import AgentAdapter, register
from herdr_client import run_cmd, get_pane_info, get_pane_text


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*(\x07|\x1b\\)")

# opencode TUI permission dialog stage markers (plain-text substrings, source-verified).
ALWAYS_CONFIRM_MARKERS = ("Always allow", "until OpenCode is restarted")
REJECT_MARKERS = ("Reject permission", "Tell OpenCode what to do differently")


def strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences so plain-text stage markers and commands are regex-matchable."""
    if not text:
        return ""
    return ANSI_ESCAPE_RE.sub("", text)


def decide_opencode_injection(stage: str, agent_status: str) -> str:
    """Pure decision function for the post-inject fail-safe backstop.

    Maps (dialog_stage, agent_status) to one of:
      'always_abort'   : our enter landed on 'always' -> caller sends escape.
      'not_registered' : dialog still at 'permission' -> enter did not register.
      'ambiguous'      : stage unknown AND agent still blocked -> do NOT treat as success.
      'success'        : dialog cleared AND agent no longer blocked (positive signal).

    Kept pure (no subprocess/Herdr) so the ladder can be unit-tested.
    """
    if stage == "always_confirm":
        return "always_abort"
    if stage == "permission":
        return "not_registered"
    # stage 'unknown' (no recognized dialog marker): success requires a positive
    # signal that the agent is no longer blocked (i.e. the command started running).
    if agent_status != "blocked":
        return "success"
    return "ambiguous"


@register
class OpenCodeAdapter(AgentAdapter):
    kind = "opencode"

    blocked_markers = ("Permission required", "Allow once", "Allow always")

    def classify_dialog_stage(self, visible_text: str) -> str:
        """Classify the opencode dialog stage: 'always_confirm' | 'reject' | 'permission' | 'unknown'."""
        text = strip_ansi(visible_text)
        if any(m in text for m in ALWAYS_CONFIRM_MARKERS):
            return "always_confirm"
        if any(m in text for m in REJECT_MARKERS):
            return "reject"
        if "Permission required" in text or "Allow once" in text:
            return "permission"
        return "unknown"

    def parse_permission_request(self, visible_text: str):
        """Extract the command/action from an opencode permission dialog.

        Only parses when the dialog is at the 'permission' stage; returns None
        otherwise (so the watcher aborts injection — see the Q3 fail-safe ladder).

        TODO(weakness): dialog layout is source-inferred, not empirically captured.
        Finalize the $ <command> / file-path regexes against a live opencode dialog
        capture (herdr agent read --source detection) before trusting full command
        extraction.
        """
        text = strip_ansi(visible_text)
        if self.classify_dialog_stage(text) != "permission":
            return None

        # 1. Bash command: "$ <command>"
        m = re.search(r"\$\s*([^\n]+)", text)
        if m:
            cmd = m.group(1).strip()
            if cmd:
                return cmd

        # 2. File edit / write path
        m = re.search(r"(?:Edit|Write|Create)\s+(?:file\s+)?([~/][^\s]+)", text, re.IGNORECASE)
        if m:
            return f"edit_file {m.group(1).strip()}"

        # 3. webfetch URL
        m = re.search(r"https?://[^\s)\]]+", text)
        if m:
            return f"webfetch {m.group(0).strip()}"

        return None

    def inject_approval(self, pane_id, req_cmd):
        """Inject a single 'enter' via the Q3 fail-safe ladder with bounded re-poll.

        Returns (approved: bool, reason: str).
        """
        # Step 4: inject a single enter (no arrows/numbers).
        run_cmd(["herdr", "agent", "send-keys", pane_id, "enter"])

        # Step 5: post-inject self-correction backstop via bounded re-poll. A single
        # timed read would misclassify mid-redraw flicker as 'unknown' (success), so we
        # re-poll until the dialog stage stabilizes or a positive signal appears.
        for _ in range(5):
            time.sleep(0.1)
            stage = self.classify_dialog_stage(get_pane_text(pane_id, lines=80))
            status = (get_pane_info(pane_id) or {}).get("agent_status", "")
            verdict = decide_opencode_injection(stage, status)

            if verdict == "always_abort":
                run_cmd(["herdr", "agent", "send-keys", pane_id, "escape"])
                return False, "post-inject: 'always' confirmation detected; aborted via escape"
            if verdict == "success":
                print(f"🚀 Auto-approving opencode 'once' for {pane_id}...", flush=True)
                return True, "once approved (dialog cleared, agent no longer blocked)"
            if verdict == "ambiguous":
                return False, "post-inject: ambiguous state; not approved"
            # 'not_registered' -> keep polling in case of a mid-redraw flicker.

        return False, "post-inject: dialog still at 'permission' after bounded re-poll; enter not registered"
