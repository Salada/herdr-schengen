"""OpenCode adapter — permission dialog parsing and Q3 fail-safe key injection.

opencode's permission dialog is a horizontal button row
{once:"Allow once", always:"Allow always", reject:"Reject"} rendered on the
alternate-screen Bubble Tea TUI, with 'once' pre-selected on fresh mount
(source-verified: selected = keys[0]). A single `enter` deterministically
selects 'once'; arrows/numbers are NOT supported and MUST NOT be sent.
"""

import os
import re
import time

from herdr_client import get_pane_text, run_cmd

from agent_adapters.base import AgentAdapter, register

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*(\x07|\x1b\\)")

# Box-drawing / block-element glyphs rendered by the Bubble Tea panel border
# (e.g. '┃' U+2503, '│' U+2502, '─' U+2500). These are terminal-margin artifacts
# that wrap around each visual line of the dialog and MUST NOT leak into an
# extracted command (they otherwise corrupt multi-line captures and make the AST
# evaluator fail with "invalid character").
BOX_DRAWING_RE = re.compile(r"[\u2500-\u257F\u2580-\u259F]")

# opencode TUI permission dialog stage markers (plain-text substrings, source-verified).
ALWAYS_CONFIRM_MARKERS = ("Always allow", "until OpenCode is restarted")
REJECT_MARKERS = ("Reject permission", "Tell OpenCode what to do differently")


def strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences so plain-text stage markers and commands are regex-matchable."""
    if not text:
        return ""
    return ANSI_ESCAPE_RE.sub("", text)


def strip_tui(text: str) -> str:
    """Strip ANSI escapes AND TUI box-drawing/block glyphs from pane text."""
    return BOX_DRAWING_RE.sub("", strip_ansi(text))


_COST_METADATA_RE = re.compile(r"^\d+(?:\.\d+)?\s*(?:spent|tokens|k|m)?$", re.IGNORECASE)


def _looks_like_cost_metadata(cmd: str) -> bool:
    """True if the extracted string is a cost/token metadata value (e.g. '0.93 spent')."""
    return bool(_COST_METADATA_RE.match(cmd.strip()))


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

    'always' renders as a stable, visible confirmation screen. 'reject' renders a
    confirmation screen for sub-agents only — the top-level agent rejects immediately,
    which text alone cannot distinguish from 'once' (a known structural limitation of
    single-enter + text post-verification). If either confirm screen appears anywhere in
    the sequence we must abort (send escape) rather than misclassify a human-residual
    cursor position as success. Otherwise, a cleared dialog (final stage 'unknown') with
    no confirm screen appearing means 'once' was applied — this removes any dependency on
    Herdr's agent_status latency.

    Returns (verdict, reason) where verdict is
    'success' | 'always_abort' | 'reject_abort' | 'not_registered'.
    """
    if any(s == "always_confirm" for s in stages):
        return "always_abort", "post-inject: 'always' confirmation detected; aborted via escape"
    if any(s == "reject" for s in stages):
        return "reject_abort", "post-inject: 'reject' confirmation detected (human residual cursor); aborted via escape"
    if stages and stages[-1] == "permission":
        return "not_registered", "post-inject: dialog still at 'permission' after bounded re-poll; enter not registered"
    # Success requires TWO consecutive cleared ('unknown') stages — a single
    # transient 'unknown' (mid-redraw flicker) must not be misread as the dialog
    # being gone while the permission prompt is still live.
    if len(stages) >= 2 and stages[-1] == "unknown" and stages[-2] == "unknown":
        return "success", "once approved (dialog cleared for 2 consecutive polls, no always/reject confirm)"
    return "not_registered", "post-inject: dialog not confirmed cleared after bounded re-poll; enter not registered"


@register
class OpenCodeAdapter(AgentAdapter):
    kind = "opencode"

    blocked_markers = ("Permission required", "Allow once", "Allow always")

    def classify_dialog_stage(self, visible_text: str) -> str:
        """Classify the opencode dialog stage: 'always_confirm' | 'reject' | 'permission' | 'unknown'.

        Anchored to the LATEST (bottom) dialog: confirm/reject markers are only
        recognized after the last "Permission required" header. An unanchored
        substring search would match a stale marker in the transcript history
        (e.g. a code diff printing "Always allow") and misclassify the live
        permission dialog as a confirm stage -> hang.
        """
        text = strip_tui(visible_text)
        header_idx = text.rfind("Permission required")
        tail = text[header_idx:] if header_idx != -1 else text
        if any(m in tail for m in ALWAYS_CONFIRM_MARKERS):
            return "always_confirm"
        if any(m in tail for m in REJECT_MARKERS):
            return "reject"
        if "Permission required" in tail or "Allow once" in tail:
            return "permission"
        return "unknown"

    def parse_permission_request(self, visible_text: str):
        """Extract the command/action from an opencode permission dialog.

        Only parses when the dialog is at the 'permission' stage; returns None
        otherwise (so the watcher aborts injection — see the Q3 fail-safe ladder).

        Layout is source-verified against packages/tui/src/routes/session/permission.tsx:
        the dialog renders as a banner with header "Permission required", a per-tool title
        (e.g. "Shell command" for bash), a body ("$ <command>" for bash), and option buttons
        "Allow once"/"Allow always"/"Reject".

        Extraction is anchored to the dialog region (between "Permission required" and
        "Allow once") because the chat timeline ALSO renders past commands as
        "$ <command>", and the sidebar renders cost metadata "$0.93 spent". An unanchored
        search would match the first "$ " in the viewport — a past (safe) command or cost —
        instead of the current request, causing a fail-open where a dangerous command is
        auto-approved as if it were benign.
        """
        text = strip_tui(visible_text)
        if self.classify_dialog_stage(text) != "permission":
            return None

        # Anchor to the dialog region. Use rfind (not find) so the LATEST rendered
        # dialog at the bottom is anchored, not a stale "Permission required"/"Allow once"
        # string in the transcript history above (which would slice the wrong region).
        header_idx = text.rfind("Permission required")
        allow_idx = text.rfind("Allow once")
        start = header_idx if header_idx != -1 else 0
        region = text[start:allow_idx] if allow_idx > start else text[start:]

        # 1. Bash command: "$ <command>" (whitespace after '$' is mandatory, so the
        #    sidebar cost "$0.93 spent" — no whitespace after '$' — is not matched).
        #
        #    Capture the FULL command to the end of the region (which terminates at
        #    "Allow once"), not just the first line. The TUI soft-wraps long commands
        #    onto multiple screen lines (real newlines in the captured pane text), so a
        #    first-line-only capture would silently drop a dangerous suffix — e.g.
        #    "git status; rm -rf /" wrapped after the space becomes "git status;" and the
        #    "rm -rf /" tail is lost, a fail-open. Rejoin real newlines with single
        #    spaces; literal backslash-n sequences (multi-line command bodies, see the
        #    external-directory "Patterns" case) are not whitespace and are normalized to
        #    a separator space so word-boundary evaluator patterns still match.
        m = re.search(r"\$\s+([\s\S]+)", region)
        if m:
            cmd = m.group(1).replace("\\n", " ")
            cmd = re.sub(r"\s+", " ", cmd).strip()
            if cmd and not _looks_like_cost_metadata(cmd):
                return cmd

        # 2. External directory access: "Access external directory <dir>" (with
        #    "Patterns" body). Mapped to access_directory so the evaluator can apply
        #    SECRET_GUARD / SANDBOX_GUARD / GRAY_ZONE screening to the directory.
        #    Capture the FULL directory path — including spaces ("/Volumes/My Drive/.ssh")
        #    AND real-newline soft-wraps ("/very/long/.../wraps\n/onto/second/.ssh") — up to
        #    the "Patterns" body (anchored to LINE START so a path containing the substring
        #    "Patterns", e.g. "/home/Patterns-dir/.ssh", is not truncated) or a literal
        #    backslash-n. A first-line-only capture would drop a wrapped sensitive tail, a
        #    fail-open; rejoin real newlines with spaces.
        m = re.search(r"Access external directory\s+([^\\]+?)(?=\n\s*Patterns\b|\s*\\n|$)", region)
        if m:
            dir_path = re.sub(r"\s+", " ", m.group(1)).strip()
            return f"access_directory {dir_path}"

        # 3. File edit / write path — capture the path up to the first real newline or a
        #    literal backslash (the title line only). The edit dialog also renders an
        #    EditBody diff after the title, which must NOT be swallowed, so capture is
        #    intentionally single-line (space-in-path safe; soft-wrapped edit paths are a
        #    documented residual limitation pending host verification of the body boundary).
        m = re.search(r"(?:Edit|Write|Create)\s+(?:file\s+)?([~/][^\n\\]+)", region, re.IGNORECASE)
        if m:
            return f"edit_file {m.group(1).strip()}"

        # 4. File read: "Read <path>" -> read_file, so the evaluator applies SECRET_GUARD
        #    (e.g. reading ".env", "id_*") and GRAY_ZONE screening to the path.
        m = re.search(r"\bRead\b\s+(?:file\s+)?([~/][^\n\\]+)", region, re.IGNORECASE)
        if m:
            return f"read_file {m.group(1).strip()}"

        # 5. webfetch URL
        m = re.search(r"https?://[^\s)\]]+", region)
        if m:
            return f"webfetch {m.group(0).strip()}"

        # 6. Doom loop: the agent is stuck in a repetition loop. Never auto-approve —
        #    always escalate so the human can intervene.
        if re.search(r"doom\s*loop", region, re.IGNORECASE):
            return "doom_loop"

        # 7. Fallback: any other permission type (glob/grep/list/task/websearch/unknown).
        #    Escalate carrying the dialog title — never silently skip or auto-approve an
        #    unhandled request. Skip the header and sidebar cost metadata (which can leak
        #    into the region while the dialog is still rendering -> transient, re-poll).
        title = None
        for ln in region.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("Permission required") or ln.startswith("$"):
                continue
            if re.match(r"^[\d,]+(?:\s+(?:spent|tokens|k|m))?$", ln, re.IGNORECASE):
                continue
            title = ln
            break
        if title is None:
            return None
        return f"unhandled_dialog {title}"

    def inject_approval(self, pane_id, req_cmd):
        """Inject 'enter' via the Q3 fail-safe ladder with bounded re-poll and retry.

        Returns (approved: bool, reason: str).

        A single `send-keys enter` can be lost if the dialog's key bindings are
        not yet registered (Bubble Tea renders asynchronously), so if the dialog
        is still at 'permission' after the re-poll window, we retry the enter
        (bounded by SCHENGEN_OPENCODE_MAX_INJECT). Before EVERY enter — including
        each retry — the live dialog is re-read and re-parsed, and the enter is
        only sent while it still shows the SAME request (req_cmd). If the dialog
        cleared (success) or switched to a different permission, we stop: a retry
        must never approve a different (possibly dangerous) command.
        """
        try:
            poll_seconds = float(os.environ.get("SCHENGEN_OPENCODE_REPOLL_SECONDS", "2.5"))
        except ValueError:
            poll_seconds = 2.5
        try:
            max_attempts = int(os.environ.get("SCHENGEN_OPENCODE_MAX_INJECT", "3"))
        except ValueError:
            max_attempts = 3
        poll_interval = 0.25

        reason = "post-inject: dialog not confirmed cleared after bounded re-poll; enter not registered"
        for _ in range(max(1, max_attempts)):
            # TOCTOU re-verification BEFORE each enter: the live dialog must still
            # show the SAME permission request. A retry must not approve a
            # different (possibly dangerous) command that appeared meanwhile.
            visible = get_pane_text(pane_id, lines=80)
            live_stage = self.classify_dialog_stage(visible)
            if live_stage != "permission":
                if live_stage == "unknown":
                    print(f"🚀 Auto-approving opencode 'once' for {pane_id}...", flush=True)
                    return True, "once approved (dialog cleared)"
                return False, f"post-inject: dialog moved to '{live_stage}' before inject; aborted"
            if self.parse_permission_request(visible) != req_cmd:
                return False, "post-inject: dialog command changed before inject; aborted (TOCTOU)"

            # Inject a single enter (no arrows/numbers). run_cmd returns None on
            # subprocess failure (herdr_client swallows CalledProcessError).
            if run_cmd(["herdr", "agent", "send-keys", pane_id, "enter"]) is None:
                return False, "send-keys failed (herdr CLI error); enter not delivered"

            # Post-inject self-correction backstop via bounded re-poll.
            deadline = time.monotonic() + poll_seconds
            stages = []
            consecutive_unknown = 0
            while time.monotonic() < deadline:
                stage = self.classify_dialog_stage(get_pane_text(pane_id, lines=80))
                stages.append(stage)
                if stage == "unknown":
                    consecutive_unknown += 1
                    if consecutive_unknown >= 2:
                        break
                else:
                    consecutive_unknown = 0
                    if stage in ("always_confirm", "reject"):
                        break
                time.sleep(poll_interval)

            verdict, reason = resolve_opencode_injection(stages)
            if verdict in ("always_abort", "reject_abort"):
                # A human-residual cursor position (on 'always' or 'reject') was hit by our
                # enter. Press escape to exit the confirmation sub-dialog, and return the
                # reason so the caller escalates (conveying it to the human via Herdr).
                run_cmd(["herdr", "agent", "send-keys", pane_id, "escape"])
                return False, reason
            if verdict == "success":
                print(f"🚀 Auto-approving opencode 'once' for {pane_id}...", flush=True)
                return True, reason
            # verdict == "not_registered" -> dialog still at 'permission'; retry
            # (the next loop iteration re-verifies the dialog before re-entering).

        return False, reason
