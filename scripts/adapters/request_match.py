"""Directional request-command matcher for TOCTOU re-parse guards (AGENTS.md rule 14).

Fixes incidents #3143/#3219 (key-injection drop): the live pane-text re-parse of
an opencode permission dialog can differ from the FULL canonical request command
(``req_cmd``) that the gatekeeper evaluated —

* a terminal viewport soft-wrap can TRUNCATE the captured text to a prefix of
  the approved command, and
* ``access_directory`` grants can render with path-expression variance
  (``~`` vs absolute, parent dir vs file inside it, glob vs concrete path).

``same_request(approved_cmd, screen_cmd)`` decides whether the live re-parse
still shows the SAME permission request:

* ``approved_cmd`` = the FULL canonical request the gatekeeper evaluated (ground truth).
* ``screen_cmd``   = the LIVE re-parse (possibly truncated / path-variant).

DIRECTIONALITY IS CRITICAL (fail-closed): screen may be a truncated PREFIX of
approved (same dialog -> match), but a SUPERSET of approved (e.g. the agent
appended ``&& rm -rf /`` after the gatekeeper approved) is a DIFFERENT — and
potentially dangerous — request and MUST NEVER match. ``same_request`` is
intentionally NOT symmetric.

The pure normalization ``norm_req_cmd`` stays SURGICAL (strip leading ``$ ``
prompt + collapse whitespace ONLY — issue #23/#1910, pinned by
TestNormReqCmd); the prefix / upper-directory / glob tolerance lives HERE, not
inside ``norm_req_cmd``.

Stdlib only (os, re, fnmatch): importable by any adapter / coordinator without
pulling the evaluator or herdr_client (keeps the INV-AA-9 layering invariant —
the adapter layer never imports the evaluator).
"""

import fnmatch
import os
import re

# Minimum length of the APPROVED (full) command for prefix-truncation
# tolerance: a command shorter than this fits on a single viewport line, so a
# shorter live re-parse is a DIFFERENT request, not a truncated rendering of
# the same dialog (e.g. "ls" vs "ls -la /tmp/foo").
MIN_PREFIX_LEN = int(os.environ.get("SCHENGEN_PREFIX_MATCH_MIN_LEN", "16"))

# access_directory is the one permission where the request is a bare directory
# grant — the canonical form is "access_directory <path>".
_ACCESS_DIR_RE = re.compile(r"^access_directory\s+(.+)$", re.IGNORECASE)


def norm_req_cmd(s) -> str:
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


def _is_path_inclusive(approved: str, screen: str) -> bool:
    """True for ``access_directory`` path-expression variance of the SAME grant.

    access_directory is the one permission type where the canonical request
    (channel filepath / pane-text dir) and the live re-parse can legitimately
    differ in PATH EXPRESSION while still being the same directory grant:
      - screen is an ancestor directory of approved (parent dir vs file inside);
      - screen is a glob covering approved (dir/* vs the concrete path);
      - ``~`` vs absolute spelling of the same directory.
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
        return fnmatch.fnmatch(pa, pb)
    return pa.startswith(pb.rstrip(os.sep) + os.sep)


def same_request(approved_cmd, screen_cmd) -> bool:
    """Directional: does the live re-parse (``screen_cmd``) still show the SAME
    permission request as the gatekeeper-evaluated ``approved_cmd``?

    Match when (after surgical normalization) they are EQUAL, when screen is a
    plausible viewport-TRUNCATED whitespace-boundary prefix of approved with the
    full approved command long enough (>= MIN_PREFIX_LEN), or when
    approved/screen are ``access_directory`` variants of the same directory
    grant (ancestor / glob / ~-vs-absolute). A screen that is a SUPERSET of
    approved — the agent appended a dangerous suffix after approval — never
    matches (fail-closed).
    """
    approved = norm_req_cmd(approved_cmd)
    screen = norm_req_cmd(screen_cmd)
    if not approved or not screen:
        return False
    if approved == screen:
        return True
    if _is_prefix_truncated(approved, screen):
        return True
    if _is_path_inclusive(approved, screen):
        return True
    return False
