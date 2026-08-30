"""OpenCode adapter — permission dialog parsing and Q3 fail-safe key injection.

opencode's permission dialog is a horizontal button row
{once:"Allow once", always:"Allow always", reject:"Reject"} rendered on the
alternate-screen Bubble Tea TUI, with 'once' pre-selected on fresh mount
(source-verified: selected = keys[0]). A single `enter` deterministically
selects 'once'; arrows/numbers are NOT supported and MUST NOT be sent.
"""

import json
import os
import re
import time
from pathlib import Path

from adapters.herdr_client import get_pane_text, run_cmd

from adapters.agent_adapters.base import INJECT_SKIP_CHANGED, AgentAdapter, footer_is_live, register

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


# OpenCode TUI auxiliary text (right sidebar + bottom status bar) that leaks into
# the captured pane text and corrupts command extraction. These fragments are not
# part of the agent's command and MUST be stripped so parsing is stable across
# polls (otherwise the TOCTOU re-parse differs from the original req_cmd and
# falsely aborts injection, or a garbled command is evaluated).
_LEAKED_TEXT_RE = re.compile(
    r"(?:"
    r"~[^\s]*:[^\s]+"                                    # status bar "~/code/herdr-schengen:main"
    r"|\d[\d,]*\s+tokens?"                               # "106,830 tokens" (token counter)
    r"|\d+(?:\.\d+)?% used"                              # "13% used"
    r"|\d+(?:\.\d+)?[KM]\s*\(\d+%\)\s*·\s*\$[\d.]+"      # "106.8K (11%) · $0.05"
    r"|\$\d+\.\d+\s+spent"                               # "$0.07 spent"
    r"|\d+(?:\.\d+)?% used"                              # "13% used"
    r"|LSPs? will activate as files are read"            # LSP hint
    r"|\bsalada-nas Connected\b"                         # MCP status
    r"|• pyright"                                        # LSP server name
    r"|OpenCode \d+\.\d+\.\d+"                           # version
    r"|Build · [^\s]*"                                    # model name (any provider)
    r"|esc interrupt"                                    # keybinding
    r"|ctrl\+[a-z]+ [a-z]+"                              # "ctrl+f fullscreen" / "ctrl+p commands"
    r"|\bQUEUED\b"                                       # session status
    r"|\bThinking\b|\bReading file[^\s]*\b|\bWriting command[^\s]*\b"  # progress indicators
    r"|\bLSP\b|\bMCP\b"                                  # standalone sidebar labels
    r")"
)


def strip_leaked_text(text: str) -> str:
    """Strip OpenCode TUI sidebar/status-bar fragments that leak into pane text.

    Preserves newlines (the region/command extraction relies on line structure);
    the extracted command itself is whitespace-collapsed by the callers.
    """
    return _LEAKED_TEXT_RE.sub(" ", text)


def _looks_like_cost_metadata(cmd: str) -> bool:
    """True if the extracted string is a cost/token metadata value (e.g. '0.93 spent')."""
    return bool(_COST_METADATA_RE.match(cmd.strip()))


# Numbered option row ("1. Production", "3. Type your own answer") in the question
# dialog. Option rows are the only numbered content in the dialog body.
_OPTION_NUM_RE = re.compile(r"^\d+\.\s")


def _extract_question_text(text: str):
    """Extract the human question text from an opencode question dialog.

    Source-verified layout (packages/tui/src/routes/session/question.tsx): the
    dialog body is a left-bordered column; after `strip_tui` removes the `┃`
    border, the question text is the first body block (2-space indent), above the
    numbered option rows (`N. label`, same indent) and their deeper-indented
    description rows (5-space), above the footer keybinding row. We anchor on the
    constant footer marker `esc dismiss`, exclude the footer row, then recover the
    question text as the contiguous non-empty block directly above the option rows.

    This is only for human-readable escalation/log summaries — the question is
    never auto-approved regardless, so a sub-optimal extraction is fail-safe, not
    a security issue.
    """
    m = re.search(r"\besc\s+dismiss\b", text)
    if not m:
        return None
    lines = text[:m.start()].splitlines()

    # Option rows are all at the same indent; use it to distinguish the question
    # text (same indent, non-numbered) from indented description rows (deeper).
    option_indent = None
    for ln in lines:
        st = ln.strip()
        if _OPTION_NUM_RE.match(st):
            option_indent = len(ln) - len(ln.lstrip(" \t"))
            break

    qlines = []
    for ln in reversed(lines):
        st = ln.strip()
        if not st:
            if qlines:
                break  # blank line above the question text -> done
            continue
        if "↑↓" in st or "⇆" in st or st.startswith("enter "):
            continue  # footer keybinding row (truncated at the `esc dismiss` anchor)
        if _OPTION_NUM_RE.match(st):
            continue  # numbered option row / "N. Type your own answer"
        if option_indent is not None:
            indent = len(ln) - len(ln.lstrip(" \t"))
            if indent > option_indent:
                continue  # indented description row under an option
            if indent < option_indent:
                break  # less-indented transcript content above the dialog
        qlines.append(st)
    qlines.reverse()
    q = re.sub(r"\s+", " ", " ".join(qlines)).strip()
    if not q:
        return None
    return q[:160]


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


# ---- Structured permission channel (issue #57, extraction-reliability) ----
# Each guarded OpenCode pane's plugin (schengen-host.js) observes opencode's
# `permission.asked` event and writes the CLEAN request (no terminal-text leak)
# to a per-pane JSON file. This adapter reads that file as the primary command
# source, falling back to pane-text scraping when no fresh event exists (fail
# closed — never silently trust a missing/garbled channel).

CHANNEL_DIR = Path.home() / ".local" / "state" / "herdr-schengen" / "opencode_permissions"
# Issue #23/#1910: a gatekeeper LLM adjudication takes MINUTES, so the permission
# event must not stale out while the dialog is still pending. Kept overridable.
CHANNEL_TTL_SECONDS = float(os.environ.get("SCHENGEN_OPENCODE_CHANNEL_TTL", "3600"))


def _norm_req_cmd(s) -> str:
    """Canonicalize a request-command for equality comparison (issue #23/#1910).

    A channel-sourced raw_command and a pane-text re-parse of the SAME dialog can
    differ by a leading shell-prompt '$ ' or by whitespace (soft-wrap / extra
    spaces). Strip a leading '$ ' prompt and collapse whitespace ONLY. Do NOT use
    normalize_command: it collapses security-relevant fields (paths, quoted
    payloads, hashes, versions) to placeholders, which would weaken the
    INJECT_SKIP_CHANGED guard and approve a DIFFERENT command.
    """
    s = (s or "").strip()
    s = re.sub(r"^\$\s+", "", s)
    return re.sub(r"\s+", " ", s)


def _sanitize_pane_id(pane_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", pane_id or "unknown")


def _channel_file(pane_id: str) -> Path:
    return CHANNEL_DIR / f"{_sanitize_pane_id(pane_id)}.json"


def read_channel_event(pane_id: str):
    """Return the latest `permission.asked` event for a pane, or None if missing/stale.

    The plugin overwrites the file on each ask, so the file holds the single
    latest event. A parse error (mid-write) or a stale timestamp yields None so
    the caller falls back to pane-text scraping.
    """
    try:
        data = json.loads(_channel_file(pane_id).read_text())
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("permission"):
        return None
    if time.time() - float(data.get("ts", 0)) > CHANNEL_TTL_SECONDS:
        return None
    return data


def channel_event_to_req_cmd(event):
    """Map a structured `permission.asked` event to the adapter's req_cmd format.

    Field mapping is source-verified against opencode (packages/opencode/src/tool/):
    - bash: the FULL command string is `metadata.command` (patterns are per-AST-node
      substrings and can split `a && b` into separate entries).
    - external_directory: the path is `metadata.filepath`/`parentDir` (patterns is a
      `dir/*` glob, not the path).
    - edit/read/webfetch: path/url in `patterns[0]` (edit full path in metadata.filepath).
    """
    permission = event.get("permission", "")
    metadata = event.get("metadata") or {}
    patterns = event.get("patterns") or []
    if not isinstance(patterns, list):
        patterns = []

    if permission == "bash":
        cmd = metadata.get("command") or " ".join(str(p) for p in patterns).strip()
        return cmd or None

    if permission == "external_directory":
        dirs = metadata.get("directories") or []
        path = (
            metadata.get("filepath")
            or metadata.get("parentDir")
            or (dirs[0] if dirs else None)
            or (patterns[0] if patterns else None)
        )
        if path:
            return f"access_directory {path}"
        return None

    if permission in ("edit", "write"):
        path = metadata.get("filepath") or (patterns[0] if patterns else None)
        if path:
            return f"edit_file {path}"
        return None

    if permission == "read":
        path = patterns[0] if patterns else None
        if path:
            return f"read_file {path}"
        return None

    if permission == "webfetch":
        url = patterns[0] if patterns else None
        if url:
            return f"webfetch {url}"
        return None

    if permission:
        return f"unhandled_dialog {permission}"
    return None


# Decision channel (issue #57 full closure): the watcher writes an approve/reject
# decision (permission_id + response) to a per-pane JSON file; the opencode host
# plugin polls it and replies programmatically via client.permission — approval
# is bound to the exact permission_id (no bare `send-keys enter` on the dialog).
DECISION_DIR = Path.home() / ".local" / "state" / "herdr-schengen" / "opencode_decisions"


def _decision_file(pane_id: str) -> Path:
    return DECISION_DIR / f"{_sanitize_pane_id(pane_id)}.json"


def write_decision(pane_id: str, permission_id: str, response: str = "once") -> None:
    """Write an approve/reject decision for a permission_id to the pane's decision file."""
    try:
        DECISION_DIR.mkdir(parents=True, exist_ok=True)
        _decision_file(pane_id).write_text(
            json.dumps({
                "pane_id": pane_id,
                "permission_id": permission_id,
                "response": response,
                "ts": time.time(),
            })
        )
    except OSError:
        pass


@register
class OpenCodeAdapter(AgentAdapter):
    kind = "opencode"

    blocked_markers = ("Permission required", "Allow once", "Allow always")

    def dialog_is_live(self, visible_text: str) -> bool:
        """True only if the ACTIVE (bottom) opencode permission dialog is live.

        classify_dialog_stage is rfind-anchored to the LATEST "Permission required"
        header, so this is stricter than get_pending_request (which may fall back
        to a stale structured-channel event for a resolved dialog).
        """
        return self.classify_dialog_stage(visible_text) == "permission"

    def classify_dialog_stage(self, visible_text: str) -> str:
        """Classify the opencode dialog stage: 'always_confirm' | 'reject' | 'permission' | 'unknown'.

        Anchored to the LATEST (bottom) dialog: confirm/reject markers are only
        recognized after the last "Permission required" header. An unanchored
        substring search would match a stale marker in the transcript history
        (e.g. a code diff printing "Always allow") and misclassify the live
        permission dialog as a confirm stage -> hang.
        """
        text = strip_leaked_text(strip_tui(visible_text))
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
        text = strip_leaked_text(strip_tui(visible_text))

        # 0. Human question dialog ("↑↓ select  enter submit  esc dismiss"): the
        #    agent is asking the user a question. Never auto-approve; return a
        #    sentinel so the watcher leaves it for the human instead of silently
        #    skipping it. `esc dismiss` is the constant, question-dialog-unique
        #    footer marker (the permission dialog footer is `esc cancel`), so it
        #    anchors detection across all question states (single, multi-select,
        #    multi-question, confirm tab). The question text is extracted so the
        #    escalation/log message shows what was actually asked.
        if footer_is_live(text, "esc dismiss"):
            q = _extract_question_text(text)
            return f"question: {q}" if q else "question"

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

    def get_pending_request(self, pane_id, visible_text):
        """Return the pending command/action using the structured channel when a
        live permission dialog is up, falling back to pane-text parsing.

        The channel is gated on the dialog STAGE (classify_dialog_stage ==
        "permission") so a resolved/cleared dialog (stage != permission) never
        re-uses a stale channel event — it falls through to the pane-text parser
        (which returns None when the dialog is gone).
        """
        if self.classify_dialog_stage(visible_text) == "permission":
            event = read_channel_event(pane_id)
            if event:
                cmd = channel_event_to_req_cmd(event)
                if cmd:
                    return cmd
        return self.parse_permission_request(visible_text)

    def channel_approve(self, pane_id, req_cmd):
        """Channel-based approve (issue #57 full closure): write a decision bound
        to the exact permission_id; the host plugin replies via client.permission.
        No bare `send-keys enter` on the live dialog.
        """
        event = read_channel_event(pane_id)
        if not event or not event.get("permission_id"):
            return False, "no channel permission"
        # Normalized comparison (issue #23/#1910): the channel-sourced command and
        # req_cmd may differ by prompt prefix / whitespace; only a REAL command
        # mismatch (a different permission request) must yield INJECT_SKIP_CHANGED.
        if _norm_req_cmd(channel_event_to_req_cmd(event)) != _norm_req_cmd(req_cmd):
            return False, INJECT_SKIP_CHANGED
        write_decision(pane_id, event["permission_id"], "once")
        return True, "permission.reply decision written (permission_id bound)"

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
        injected_once = False
        for _ in range(max(1, max_attempts)):
            # TOCTOU re-verification BEFORE each enter: the live dialog must still
            # show the SAME permission request. A retry must not approve a
            # different (possibly dangerous) command that appeared meanwhile.
            visible = get_pane_text(pane_id, lines=80)
            live_stage = self.classify_dialog_stage(visible)
            if live_stage != "permission":
                if live_stage == "unknown":
                    # Issue #23/#1910: a single 'unknown' read is NOT evidence the
                    # dialog cleared (mid-redraw flicker / stale scrollback). Do not
                    # claim success without an enter: continue to the next retry
                    # iteration, which re-reads the pane. A success return must be
                    # backed by resolve_opencode_injection's two-consecutive-cleared
                    # polls evidence AFTER an actual enter; if the budget is
                    # exhausted without confirming, we fail closed below.
                    continue
                return False, f"post-inject: dialog moved to '{live_stage}' before inject; aborted"
            # Normalized comparison (issue #23/#1910): the live pane-text re-parse
            # may render a leading '$ ' prompt or extra whitespace vs the
            # channel-sourced req_cmd — normalize both before deciding the dialog
            # trampolined to a different request.
            live_req = self.get_pending_request(pane_id, visible)
            if _norm_req_cmd(live_req) != _norm_req_cmd(req_cmd):
                # The dialog trampolined to a DIFFERENT permission request while we
                # were evaluating (e.g. "Access external directory" -> "Shell command").
                # The stale req_cmd is gone; skip so the next poll re-parses the new
                # request, instead of escalating an un-resolvable stale command.
                return False, INJECT_SKIP_CHANGED

            # Inject a single enter (no arrows/numbers). run_cmd returns None on
            # subprocess failure (herdr_client swallows CalledProcessError).
            if run_cmd(["herdr", "agent", "send-keys", pane_id, "enter"]) is None:
                return False, "send-keys failed (herdr CLI error); enter not delivered"
            injected_once = True

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

        if not injected_once:
            reason = "post-inject: dialog stage unknown; approval not confirmed"
        return False, reason
