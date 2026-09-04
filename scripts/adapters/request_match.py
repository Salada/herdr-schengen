"""Directional request-command matcher for TOCTOU re-parse guards (AGENTS.md rule 14).

Fixes incidents #3143/#3219 (key-injection drop): the live pane-text re-parse of
an opencode permission dialog can differ from the FULL canonical request command
(``req_cmd``) that the gatekeeper evaluated —

* a terminal viewport soft-wrap can TRUNCATE the captured text to a prefix of
  the approved command, and
* ``access_directory`` grants can render with path-expression variance
  (``~`` vs absolute, the immediate containing directory vs an over-specific
  file capture, same-depth glob vs concrete path).

``same_request(approved_cmd, screen_cmd)`` decides whether the live re-parse
still shows the SAME permission request:

* ``approved_cmd`` = the FULL canonical request the gatekeeper evaluated (ground truth).
* ``screen_cmd``   = the LIVE re-parse (possibly truncated / path-variant).

DIRECTIONALITY IS CRITICAL (fail-closed): screen may be a truncated PREFIX of
approved (same dialog -> match), but a SUPERSET of approved (e.g. the agent
appended ``&& rm -rf /`` after the gatekeeper approved) is a DIFFERENT — and
potentially dangerous — request and MUST NEVER match. ``same_request`` is
intentionally NOT symmetric. ``access_directory`` is a CONTAINMENT LATTICE, so
its path variance is bounded to the SAME SCOPE: only the immediate containing
directory or a same-depth glob expression of the approved path matches — never
root / grandparent / deeper ancestors, which would grant MORE scope than the
gatekeeper evaluated.

The pure normalization ``norm_req_cmd`` stays SURGICAL: it strips a leading
``$ `` prompt and collapses layout whitespace only outside quotes/heredocs.
The prefix / directory / glob tolerance lives HERE, not inside
``norm_req_cmd``.

Stdlib only (os, re, fnmatch): importable by any adapter / coordinator without
pulling the evaluator or herdr_client (keeps the INV-AA-9 layering invariant —
the adapter layer never imports the evaluator).
"""

import fnmatch
import os
import re
import textwrap

# Minimum length of the APPROVED (full) command for prefix-truncation
# tolerance: a command shorter than this fits on a single viewport line, so a
# shorter live re-parse is a DIFFERENT request, not a truncated rendering of
# the same dialog (e.g. "ls" vs "ls -la /tmp/foo").
MIN_PREFIX_LEN = int(os.environ.get("SCHENGEN_PREFIX_MATCH_MIN_LEN", "16"))

# access_directory is the one permission where the request is a bare directory
# grant — the canonical form is "access_directory <path>".
_ACCESS_DIR_RE = re.compile(r"^access_directory\s+(.+)$", re.IGNORECASE)


def preserve_executable_payload(payload: str, prompt_margin: str = "") -> str:
    """Remove only verified TUI indentation from an executable payload.

    Herdr's ``recent-unwrapped`` source already removes terminal soft wraps.
    The adapter must therefore preserve every remaining newline.  For prompt
    layouts (``$ command``), continuation rows carry the same visual margin as
    the prompt; remove exactly that prefix and retain relative indentation.
    For unprompted command blocks, ``textwrap.dedent`` removes only their common
    visual margin and likewise preserves relative indentation (notably Python).
    """
    payload = (payload or "").replace("\r\n", "\n").replace("\r", "\n")
    if prompt_margin:
        lines = payload.split("\n")
        for index in range(1, len(lines)):
            if lines[index].startswith(prompt_margin):
                lines[index] = lines[index][len(prompt_margin):]
        payload = "\n".join(lines)
    else:
        payload = textwrap.dedent(payload)
    return payload.strip()


def _norm_shell_spacing(s: str) -> str:
    """Collapse layout whitespace outside quotes, preserving quoted content."""
    out = []
    quote = None
    escaped = False
    pending_space = False
    for char in s:
        if escaped:
            out.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            out.append(char)
            escaped = True
            continue
        if char in ("'", '"'):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            if pending_space:
                out.append(" ")
                pending_space = False
            out.append(char)
            continue
        if char.isspace():
            if quote is not None:
                out.append(char)
            else:
                pending_space = bool(out)
            continue
        if pending_space:
            out.append(" ")
            pending_space = False
        out.append(char)
    return "".join(out).strip()


def norm_req_cmd(s) -> str:
    """Canonicalize layout whitespace without erasing quoted/heredoc content.

    A channel-sourced raw_command and a pane-text re-parse of the SAME dialog can
    differ by a leading shell-prompt '$ ' or by whitespace (soft-wrap / extra
    spaces). Strip a leading '$ ' prompt and collapse only non-semantic layout
    whitespace. Quoted and heredoc content is preserved. Do NOT use
    normalize_command: it collapses security-relevant fields (paths, quoted
    payloads, hashes, versions) to placeholders, which would weaken the
    INJECT_SKIP_CHANGED guard and approve a DIFFERENT command.
    """
    s = (s or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    s = re.sub(r"^\$\s+", "", s)

    # A heredoc body is data/program text, not shell layout. Preserve it byte
    # for byte (after newline normalization), including Python indentation.
    opener = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n", s)
    if opener:
        delimiter = re.escape(opener.group(2))
        closer = re.search(rf"(?m)^\t*{delimiter}[ \t]*$", s[opener.end():])
        if closer:
            body_start = opener.end()
            body_end = body_start + closer.end()
            prefix = _norm_shell_spacing(s[: opener.end() - 1])
            body = s[body_start:body_end]
            suffix = _norm_shell_spacing(s[body_end:])
            return prefix + "\n" + body + ((" " + suffix) if suffix else "")

    return _norm_shell_spacing(s)


def _is_prefix_truncated(approved: str, screen: str) -> bool:
    """True if screen is a strict, MEANINGFUL prefix of the approved command.

    The viewport soft-wrap incidents (#3143/#3219) truncate the captured pane
    text at a rendering boundary: the live re-parse equals ``approved[:k]`` cut
    at a WHITESPACE boundary (terminal word-wrap) for some k < len(approved).
    A meaningful cut must therefore land at a token boundary (the character
    after screen in approved is whitespace) — a mid-token cut is not a wrap
    artifact and stays fail-closed (defer -> re-poll -> full re-parse).

    Tolerance also requires the FULL approved command to be long enough
    (>= MIN_PREFIX_LEN) that soft-wrap truncation is plausible. Directionality:
    screen must be SHORTER than approved — a superset (agent appended a
    dangerous suffix) is a real trampoline and must never match here.
    """
    if len(approved) < MIN_PREFIX_LEN:
        return False
    return (
        len(screen) < len(approved)
        and approved.startswith(screen)
        and approved[len(screen)].isspace()
    )


def _is_soft_wrap_equivalent(approved_raw: str, screen_raw: str) -> bool:
    """Match a full canonical line to rendered newline artifacts only.

    ``recent-unwrapped`` proves that the canonical request contains no hard
    newline. A visible newline can therefore be either a word-boundary wrap
    (replace with one space) or a token/path/operator wrap (remove it). No
    non-whitespace character may be added, removed, or reordered.
    """
    if "\n" in approved_raw or "\r" in approved_raw or not re.search(r"[\r\n]", screen_raw):
        return False
    joined = re.sub(r"[\r\n][ \t]*", "", screen_raw)
    spaced = re.sub(r"[\r\n][ \t]*", " ", screen_raw)
    approved = norm_req_cmd(approved_raw)
    return approved in (norm_req_cmd(joined), norm_req_cmd(spaced))


def _has_glob(p: str) -> bool:
    """True if the path expression contains a glob metacharacter (* ? [)."""
    return any(ch in p for ch in "*?[")


def _norm_path(p: str) -> str:
    """Normalize a path expression for ancestor/glob comparison.

    expanduser + abspath first (resolves ``~`` vs absolute variance). A path
    containing glob metacharacters keeps normpath (realpath would try to resolve
    the literal '*' component); a concrete path is realpath'd to resolve symlink
    variance, falling back to normpath when realpath raises (e.g. a dangling
    component on platforms where strict resolution fails).
    """
    p = os.path.expanduser(p)
    p = os.path.abspath(p)
    if _has_glob(p):
        return os.path.normpath(p)
    try:
        return os.path.realpath(p)
    except OSError:
        return os.path.normpath(p)


def _glob_segments_match(path: str, pattern: str) -> bool:
    """fnmatch per path SEGMENT at EQUAL depth (glob '*' never crosses os.sep).

    Unlike ``fnmatch.fnmatch(path, pattern)`` — where a bare '*' spans '/' and
    lets '/a/*' match '/a/b/c/tui.py' (a scope-broadening false positive) —
    this splits both absolute paths on os.sep and fnmatches each segment at the
    SAME index. '/a/*' therefore matches '/a/b' (a DIRECT child) but never
    '/a/b/c/tui.py'. Equal segment counts keep a 'dir/*' grant expression
    anchored to the single level beneath 'dir'.
    """
    path_parts = [p for p in path.split(os.sep) if p]
    pattern_parts = [p for p in pattern.split(os.sep) if p]
    if len(path_parts) != len(pattern_parts):
        return False
    return all(fnmatch.fnmatch(seg, pat) for seg, pat in zip(path_parts, pattern_parts))


def _is_path_inclusive(approved: str, screen: str) -> bool:
    """True for ``access_directory`` path-expression variance of the SAME grant.

    access_directory is a CONTAINMENT LATTICE, so directionality must bound the
    SCOPE: a shallower path is a scope SUPERSET (broader grant). The canonical
    request is usually an over-specific capture — the plugin's filepath names
    the FILE under the directory the dialog actually grants (#3219) — so the
    ONLY sanctioned variances are:

      - ``~`` vs absolute spelling of the same directory (equality after
        normalization);
      - screen is the IMMEDIATE containing directory of the approved path
        (``os.path.dirname(approved_real) == screen_real``) — ONE level only.
        Root, grandparent, or any deeper ancestor grant MORE scope than the
        gatekeeper evaluated and NEVER match;
      - screen is a glob expression at the SAME depth as the approved path,
        matched SEGMENT-wise (a '*' in one segment never crosses '/' into a
        deeper tree).

    Deliberately access_directory ONLY: edit_file / read_file path parent/glob
    mismatches are NOT relaxed here (fail-closed) — the generic whitespace-
    boundary text-prefix tolerance above is the only leeway those kinds get.
    """
    ma = _ACCESS_DIR_RE.match(approved)
    ms = _ACCESS_DIR_RE.match(screen)
    if not ma or not ms:
        return False
    pa = _norm_path(ma.group(1))
    pb = _norm_path(ms.group(1))
    if pa == pb:
        return True
    if _has_glob(pb):
        return _glob_segments_match(pa, pb)
    # Over-specific file capture (#3219): the canonical request named a file
    # whose IMMEDIATE containing directory is the directory grant the live
    # dialog renders. ONLY that single level matches.
    return os.path.dirname(pa) == pb


def same_request(approved_cmd, screen_cmd) -> bool:
    """Directional: does the live re-parse (``screen_cmd``) still show the SAME
    permission request as the gatekeeper-evaluated ``approved_cmd``?

    Match when (after surgical normalization) they are EQUAL, when screen is a
    plausible viewport-TRUNCATED whitespace-boundary prefix of approved with the
    full approved command long enough (>= MIN_PREFIX_LEN), or when
    approved/screen are ``access_directory`` variants of the SAME directory
    scope (same path, immediate containing directory, or same-depth glob — see
    _is_path_inclusive; broader ancestors never match). A screen that is a
    SUPERSET of approved — the agent appended a dangerous suffix after
    approval — never matches (fail-closed).
    """
    approved = norm_req_cmd(approved_cmd)
    screen = norm_req_cmd(screen_cmd)
    if not approved or not screen:
        return False
    if approved == screen:
        return True
    if _is_soft_wrap_equivalent(approved_cmd or "", screen_cmd or ""):
        return True
    if _is_prefix_truncated(approved, screen):
        return True
    if _is_path_inclusive(approved, screen):
        return True
    return False
