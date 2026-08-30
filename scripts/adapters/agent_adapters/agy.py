"""AGY (Antigravity) adapter — permission prompt parsing and key injection."""

import re
from typing import Optional

from adapters.herdr_client import get_pane_text, run_cmd

from adapters.agent_adapters.base import AgentAdapter, footer_is_live, register

# AGY (Antigravity CLI) human-question dialog (live-verified): a "Question N/M:
# <text>" header + numbered option rows + "↑/↓ Navigate · enter Select · esc Skip"
# footer. This is a HUMAN question — never auto-approve; return a sentinel so the
# watcher surfaces it as a pending escalation (parity with opencode/codex #56).
_QUESTION_RE = re.compile(r"Question\s+\d+/\d+:\s*(.+)")

# #7771: every AGY approval-dialog header/footer anchor. dialog_is_live treats
# ANY of these as a live dialog — err toward "live" because the false-positive
# cost is a recoverable stuck escalation while the false-negative cost is a
# fake pane-direct APPROVED on a still-blocked agent.
_LIVE_TAIL_MARKERS = (
    "Requesting permission for:", "Do you want to proceed?", "Execute command?",
    "Do you want to run", "Accept this file edit?", "Accept this change?",
    "Pending edit", "Allow creation of this file?", "Allow creation",
    "Yes, allow creation",
)


@register
class AgyAdapter(AgentAdapter):
    kind = "agy"

    blocked_markers = (
        "Requesting permission for:",
        "Do you want to proceed?",
        "Do you want to run",
        "Execute command?",
        "> 1. Yes",
        "Accept this file edit?",
        "Accept this change?",
        "Pending edit",
        "Allow creation of this file?",
        "Allow creation",
        "Yes, allow creation",
        "How's the CLI experience so far?",
        "[0] Skip",
        "Press enter to continue",
        "[y/N]",
        "[Y/n]",
        "↑/↓ Navigate",
    )

    def dialog_is_live(self, visible_text: str) -> bool:
        """True if an ACTIVE agy approval dialog anchor is present in the tail.

        Tail-anchored superset of every AGY dialog marker (headers, footers,
        option rows, focus marker). Errs toward "live": a false positive is a
        recoverable stuck escalation, but a false negative is a fake pane-direct
        APPROVED on a still-blocked agent (#7771). Only a CLEARED dialog — none
        of the anchors in the tail — reports False.
        """
        tail = visible_text[-400:]
        tail_block = "\n".join(visible_text.splitlines()[-8:])
        return (
            footer_is_live(visible_text, "esc Skip")
            or footer_is_live(visible_text, "Press enter to continue")
            or footer_is_live(visible_text, "Do you want to proceed?")
            or footer_is_live(visible_text, "↑/↓ Navigate")
            or any(m in tail for m in _LIVE_TAIL_MARKERS)
            or "[0] Skip" in tail
            or bool(re.search(r">\s*\d+\.", tail))
            or bool(re.search(r"^\s*\d+\.\s+Yes\b", tail_block, re.MULTILINE))
            or bool(re.search(r"\[[Yy]/[Nn]\]", tail))
        )

    def question_is_live(self, visible_text: str) -> bool:
        """True if the AGY human-question dialog is live.

        Footer-keyed ("esc Skip") + the "Question N/M:" header — mirrors the
        parse gate (INV-Q-3). A cleared question dialog scrolls the footer out
        of the tail.
        """
        return footer_is_live(visible_text, "esc Skip") and _QUESTION_RE.search(visible_text) is not None

    def is_truncated(self, visible_text: str) -> bool:
        """True if the AGY dialog body is folded ("⋯ N lines hidden" marker).

        AGY renders a fold marker for long command/script bodies. A truncated
        req_cmd must NEVER reach the AST evaluator (INV-EX-2) — the watcher
        expands first (issue #2099). Accept both ellipsis codepoints (U+22EF
        midline ⋯ and U+2026 horizontal …) for the fold marker.
        """
        return bool(re.search(r"[⋯…]\s*(?:\d+\s*)?lines?\s*hidden", visible_text))

    def expand_dialog(self, pane_id: str) -> Optional[str]:
        """Expand the AGY fold via ctrl+g, then return the full dialog text.

        AGY's "⋯ lines hidden" fold is NOT in-buffer until the key materializes
        it, so send `ctrl+g` FIRST, then do a full-scrollback read. Returns None
        on read failure so the watcher fails closed (INV-EX-3).
        """
        run_cmd(["herdr", "agent", "send-keys", pane_id, "ctrl+g"])
        text = get_pane_text(pane_id, lines=500, full_dump=True)
        return text or None

    def parse_permission_request(self, visible_text):
        """Extract command/script/file-edit/survey from diverse AGY approval dialogs."""
        # 0. Human question dialog (Antigravity CLI): "Question N/M: <text>" header
        #    + "esc Skip" footer. Never auto-approve; surface as pending. The footer
        #    live-check prevents matching lingering scrollback (false positives).
        m_q = _QUESTION_RE.search(visible_text)
        if m_q and footer_is_live(visible_text, "esc Skip"):
            q = m_q.group(1).strip()
            return f"question: {q}" if q else "question"

        # Pattern 1: Standard AGY Requesting permission dialog
        m1 = re.search(r"Requesting permission for:\s*\n([\s\S]*?)\n\s*Do you want to proceed\?", visible_text)
        if m1:
            return m1.group(1).strip()

        # Pattern 2: Multi-line Command box with Requesting permission
        m2 = re.search(
            r"Command\s*\n[─-]+\s*\n\s*Requesting permission for:\s*\n([\s\S]*?)\n\s*(> 1\. Yes|Do you want to proceed)",
            visible_text,
        )
        if m2:
            return m2.group(1).strip()

        # Pattern 3: AGY File Edit Confirmation Dialog
        if (
            "Accept this file edit?" in visible_text
            or "Accept this change?" in visible_text
            or "Pending edit" in visible_text
        ):
            m_file = re.search(r"Pending edit\s*\n[─-]+\s*\n\s*([^\n\s]+)", visible_text)
            if not m_file:
                m_file = re.search(r"(/[^\s]+\.[a-zA-Z0-9_\-\.]+)\s+[+-]\d+", visible_text)
            file_path = m_file.group(1).strip() if m_file else "unknown_file"
            return f"edit_file {file_path}"

        # Pattern 3b: AGY File Creation Confirmation Dialog
        if (
            "Allow creation of this file?" in visible_text
            or "Allow creation" in visible_text
            or "Yes, allow creation" in visible_text
        ):
            m_file = re.search(r"WriteToFile\(([^\)]+)\)", visible_text)
            if not m_file:
                m_file = re.search(r"Creating file:\s*([^\n\s]+)", visible_text)
            if not m_file:
                m_file = re.search(r"(/[^\s]+\.[a-zA-Z0-9_\-\.]+)", visible_text)
            file_path = m_file.group(1).strip() if m_file else "unknown_file"
            return f"create_file {file_path}"

        # Pattern 4: Do you want to run '...'?
        m3 = re.search(r"Do you want to run\s*['\"`]([\s\S]*?)['\"`]\?", visible_text)
        if m3:
            return m3.group(1).strip()

        # Pattern 5: Execute/Run command [y/N]
        m4 = re.search(r"(?:Execute[\s\w?]*|Run\s*command\??):\s*\n([\s\S]*?)\n\s*\[[Yy]/[Nn]\]", visible_text)
        if m4:
            return m4.group(1).strip()

        # Pattern 6: Menu options (> 1. Yes) with python3 heredoc or bash command above
        if "> 1. Yes" in visible_text or "Do you want to proceed?" in visible_text:
            py_match = re.search(
                r"(python[0-9.]*\s+(?:-\s*)?<<-?\s*['\"]?([A-Za-z0-9_]+)['\"]?[\s\S]*?\n\s*\2)", visible_text
            )
            if py_match:
                return py_match.group(1).strip()
            bash_match = re.findall(r"●\s*Bash\(([\s\S]*?)\)", visible_text)
            if bash_match:
                return bash_match[-1].strip()

        # Pattern 7: CLI Experience Survey / Feedback Dialog ([0] Skip)
        tail_text = "\n".join(visible_text.splitlines()[-15:])
        if re.search(r"How's the CLI experience so far\?[\s\S]*?\[0\]\s*Skip", tail_text):
            return "feedback_survey_skip"

        return None

    def inject_approval(self, pane_id, req_cmd):
        """Inject approval keystroke(s) for an AGY dialog.

        AGY dialogs never fail after a safe evaluation, so this always returns
        approved=True.
        """
        if req_cmd == "feedback_survey_skip":
            print(f"⏩ Auto-skipping CLI experience survey on {pane_id} (sending '0')...", flush=True)
            run_cmd(["herdr", "agent", "send-keys", pane_id, "0"])
        else:
            print(f"🚀 Auto-approving pre-execution script for {pane_id} (sending Enter via SmartGate)...", flush=True)
            run_cmd(["herdr", "agent", "send-keys", pane_id, "enter"])
        return True, "approved"
