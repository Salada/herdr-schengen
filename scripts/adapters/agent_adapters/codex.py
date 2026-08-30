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

from adapters.agent_adapters.base import AgentAdapter, footer_is_live, register

# Codex input-request (question) dialog, Plan mode (live-verified): a
# "Question N/M (K unanswered)" header, the free-text question body, numbered
# option rows, then the footer "enter to submit answer". This is a HUMAN question
# — never auto-approve; recognize it so the watcher leaves it for manual response
# (parity with the opencode `question` sentinel, issue #56).
_QUESTION_FOOTER_RE = re.compile(r"enter\s+to\s+submit\s+answer", re.IGNORECASE)
_QUESTION_HEADER_RE = re.compile(r"Question\s+\d+\s*/\s*\d+\s*\([^)]*\)")
_OPTION_ROW_RE = re.compile(r"^›?\s*\d+\.\s")

# Focused-row marker of the ratatui list-selection modal: the '›' glyph precedes
# the ACTIVE (selected) option row. The liveness signal is the PRESENCE of the
# focus marker on ANY numbered row ('› 1. Yes', '› 2. No', '› 3. …'), NOT which
# option is selected — a dialog the user navigated to a non-Yes row is still a
# live dialog and must never be treated as answered. A historical prompt or an
# already-completed (enter-pressed) dialog has the marker moved off or gone
# entirely. MULTILINE so '^' anchors at each LINE start (the option row is never
# the first char of the pane read).
_ACTIVE_CHOICE_RE = re.compile(r"^\s*›\s*\d+\.", re.MULTILINE)

# #7759: current Codex edit-dialog destination lines (`Destination: <path>` /
# `File: <path>`). Tolerates a leading/trailing ratatui frame border (`│`, `├`,
# `└`, `─`, ...) and leading indentation; IGNORECASE for `destination:`/`file:`.
# MULTILINE anchors each capture to a single line so every destination is
# extracted individually (multi-file edits stay multi-capture).
_EDIT_DEST_RE = re.compile(
    r"^[│├└─┌┬┐┤┴┼\s]*(?:Destination|File):\s*(.+?)\s*[│├└─┌┬┐┤┴┼]*$",
    re.IGNORECASE | re.MULTILINE,
)

# #7938: every Codex approval-dialog header. `_latest_dialog_region` anchors the
# focused-row marker search on the LAST (bottom) dialog header — a variable
# window instead of a fixed `visible_text[-400:]` tail, so a long command body
# or multi-file diff can never overflow the window and hide a live '› N.' row.
_CODEX_DIALOG_HEADERS = (
    "Would you like to run the following command?",
    "Do you want to approve network access",
    "Would you like to send input to terminal",
    "Would you like to make the following edits?",
    "Would you like to grant these permissions?",
)


def _latest_dialog_region(visible_text: str) -> str:
    """Return the text from the LAST codex dialog header to the end of the buffer.

    Falls back to the whole text when no dialog header is present (the footer
    gate already requires a live dialog, so a header is expected in practice).
    """
    idx = -1
    for h in _CODEX_DIALOG_HEADERS:
        i = visible_text.rfind(h)
        if i > idx:
            idx = i
    return visible_text[idx:] if idx != -1 else visible_text


def _extract_codex_question_text(text: str):
    """Extract the free-text question body from a codex input-request dialog.

    Layout (live-verified):
        Question 1/1 (1 unanswered)
        <question text>
        › 1. <option>       <description>
          2. <option>
        tab to add notes | enter to submit answer | esc to interrupt

    Returns the question body (the contiguous non-empty, non-option lines after
    the header), truncated for log summaries. Only for human readability — the
    question is never auto-approved regardless.
    """
    m = _QUESTION_HEADER_RE.search(text)
    if not m:
        return None
    qlines = []
    for ln in text[m.end():].splitlines():
        st = ln.strip()
        if not st:
            if qlines:
                break
            continue
        if _OPTION_ROW_RE.match(st) or "enter to submit answer" in st or "esc to interrupt" in st:
            break
        qlines.append(st)
    q = re.sub(r"\s+", " ", " ".join(qlines)).strip()
    if not q:
        return None
    return q[:160]


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
        "enter to submit answer",
    )

    def parse_permission_request(self, visible_text):
        """Extract the command/action from a Codex approval modal."""
        # 0. Human question / input-request dialog (Plan mode). Never
        #    auto-approve; return a sentinel so the watcher leaves it for the
        #    human (parity with the opencode `question` sentinel, issue #56).
        if footer_is_live(visible_text, "enter to submit answer"):
            q = _extract_codex_question_text(visible_text)
            return f"question: {q}" if q else "question"

        # Live-dialog gate (issue #17): require the approval dialog's footer to be
        # present in the tail, so a cleared dialog lingering in the terminal
        # scrollback is not re-parsed as a pending request. The question dialog is
        # handled above with its own footer ("enter to submit answer").
        if not footer_is_live(visible_text, "Press enter to confirm or esc to cancel"):
            return None

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

        # File edit: preserve a single patch target so the evaluator can apply
        # its path-based secret, sandbox, and gray-zone checks.  Deletions,
        # multiple files, and pathless dialogs deliberately remain fail-closed.
        # Anchored to a LIVE region (rfind from the latest header + focused-row
        # '› 1. Yes' marker in the tail) so a historical header or an
        # already-completed (enter-pressed) edit dialog lingering in scrollback
        # is NOT re-parsed as a pending edit_file request (stale-pending
        # eviction).
        hdr = visible_text.rfind("Would you like to make the following edits?")
        region = visible_text[hdr:] if hdr != -1 else ""
        # #7938: region is already header-anchored via rfind — search the WHOLE
        # region (not a fixed [-400:] tail) so a long multi-file diff can never
        # overflow the window and hide the live '› N.' marker.
        if not region or not _ACTIVE_CHOICE_RE.search(region):
            return None  # historical header / already-completed edit -> NOT live

        # Legacy Codex patch header: `*** Add/Update/Delete File: <path>`
        edits = re.findall(r"^\*\*\* (Add|Update|Delete) File: (.+)$", region, re.MULTILINE)
        if edits:
            if len(edits) == 1 and edits[0][0] in ("Add", "Update"):
                return f"edit_file {edits[0][1].strip()}"
            return "edit_file"  # delete or multi-file -> fail-closed

        # Current Codex CLI format: `Destination: <path>` / `File: <path>`.
        # #7759: every destination line is captured (multi-file edits survive as
        # newline-delimited paths); a single destination is returned verbatim.
        # Pathless -> bare `edit_file` (fail-closed, INV-EF-1).
        dests = [d.strip() for d in _EDIT_DEST_RE.findall(region)]
        if len(dests) == 1:
            return f"edit_file {dests[0]}"
        if len(dests) > 1:
            return "edit_file " + "\n".join(dests)   # multi-file, newline-delimited
        return "edit_file"                            # pathless -> fail-closed

        # Permissions: Would you like to grant these permissions?
        if "Would you like to grant these permissions?" in visible_text:
            return "grant_permissions"

        return None

    def dialog_is_live(self, visible_text: str) -> bool:
        """True only if the ACTIVE codex approval dialog is genuinely open.

        Requires the dialog footer AND the focused-row '› N.' marker within the
        LATEST dialog region (header-anchored variable window, #7938) — a fixed
        [-400:] tail would overflow for long commands/multi-file diffs and
        misread a live dialog as answered. Stricter than get_pending_request
        (which only requires the footer).
        """
        if not footer_is_live(visible_text, "Press enter to confirm or esc to cancel"):
            return False
        return _ACTIVE_CHOICE_RE.search(_latest_dialog_region(visible_text)) is not None

    def question_is_live(self, visible_text: str) -> bool:
        """True if the Codex input-request (question) dialog is live.

        Footer-keyed "enter to submit answer" — mirrors the parse gate at
        parse_permission_request (INV-Q-3). A question dialog must NEVER be
        gated by the approval dialog_is_live anchors.
        """
        return footer_is_live(visible_text, "enter to submit answer")

    def inject_approval(self, pane_id, req_cmd):
        """Approve via 'y' (selection-independent, per Codex default keymap)."""
        print(f"🚀 Auto-approving codex request for {pane_id} (sending 'y')...", flush=True)
        run_cmd(["herdr", "agent", "send-keys", pane_id, "y"])
        return True, "approved (y)"
