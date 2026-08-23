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
from herdr_client import run_cmd, get_pane_text


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*(\x07|\x1b\\)")

# opencode TUI permission dialog stage markers (plain-text substrings, source-verified).
ALWAYS_CONFIRM_MARKERS = ("Always allow", "until OpenCode is restarted")
REJECT_MARKERS = ("Reject permission", "Tell OpenCode what to do differently")


def strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences so plain-text stage markers and commands are regex-matchable."""
    if not text:
        return ""
    return ANSI_ESCAPE_RE.sub("", text)


def decide_opencode_injection(stage: str) -> str:
    """Pure per-poll classification of an opencode post-inject dialog stage.

    Returns one of:
      'always_abort'   : the 'always' confirmation screen appeared -> caller sends escape.
      'not_registered' : dialog still at 'permission' -> enter did not register yet.
      'dialogue_gone'  : no recognized dialog marker (stage 'unknown').

    Kept pure (no subprocess/Herdr) so the ladder can be unit-tested.
    """
    if stage == "always_confirm":
        return "always_abort"
    if stage == "permission":
        return "not_registered"
    return "dialogue_gone"


def resolve_opencode_injection(stages):
    """Pure loop-policy function: map the observed stage sequence to a final decision.

    'always' renders as a stable, visible always-confirm screen, so if it appears
    anywhere in the sequence we must abort. Otherwise, a cleared dialog (final stage
    'unknown') with no always-confirm appearing means 'once' was applied — this removes
    any dependency on Herdr's agent_status latency.

    Returns (verdict, reason) where verdict is 'success' | 'always_abort' | 'not_registered'.
    """
    if any(s == "always_confirm" for s in stages):
        return "always_abort", "post-inject: 'always' confirmation detected; aborted via escape"
    if stages and stages[-1] == "permission":
        return "not_registered", "post-inject: dialog still at 'permission' after bounded re-poll; enter not registered"
    if stages and stages[-1] == "unknown":
        return "success", "once approved (dialog cleared, no always-confirm)"
    return "not_registered", "post-inject: no dialog signal after bounded re-poll; enter not registered"


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

        # Step 5: post-inject self-correction backstop via bounded re-poll. Collect the
        # observed stages and resolve once at the end, so a transient mid-redraw flicker
        # cannot be misclassified as success (the pure loop-policy does the final call).
        stages = []
        for _ in range(5):
            time.sleep(0.1)
            stages.append(self.classify_dialog_stage(get_pane_text(pane_id, lines=80)))

        verdict, reason = resolve_opencode_injection(stages)
        if verdict == "always_abort":
            run_cmd(["herdr", "agent", "send-keys", pane_id, "escape"])
            return False, reason
        if verdict == "success":
            print(f"🚀 Auto-approving opencode 'once' for {pane_id}...", flush=True)
            return True, reason
        return False, reason
