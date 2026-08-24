"""Partial redaction for cloud-judge calls (Phase 2).

Rule-scoped value masking that preserves key names and structure so the cloud
judge can still recognize "a secret is present here" and block, while never
shipping the plaintext secret to a third-party model.

Only a bounded set of secret *shapes* is masked (partial redaction, per-rule),
not a blanket transform. Identifiers, paths, and command structure are left
intact so the judge's safety decision is unaffected.
"""

import hashlib
import re

# (pattern, label) pairs. The value is masked; the label preserves the secret
# TYPE (api-key / aws-key / ...) so a judge can still decide "block: contains a key".
_SECRET_VALUE_RULES = [
    (re.compile(r"\b(sk-[A-Za-z0-9]{16,})"), "api-key"),
    (re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})"), "aws-key"),
    (re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,})"), "github-pat"),
    (re.compile(r"\b(AIza[A-Za-z0-9_-]{30,})"), "google-key"),
    (re.compile(r"\b(hf_[A-Za-z0-9]{20,})"), "hf-token"),
    (re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})"), "slack-token"),
    (re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), "jwt"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "private-key"),
]

# `KEY=value` / `KEY: value` assignments: keep the key NAME, mask the value.
# The key side uses a negative lookbehind (?<![A-Za-z0-9]) instead of \b so that
# underscore-prefixed compound keys (DB_PASSWORD, AWS_SECRET_ACCESS_KEY,
# MYSQL_PWD, api_key) are matched — \b treats '_' as a word char and would skip
# them, leaking the value to the cloud model.
_KEY_VALUE_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(token|secret|password|passwd|pwd|api[_-]?key|api[_-]?secret|"
    r"client[_-]?secret|access[_-]?key|credential|auth[_-]?token)s?"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^'\"\s]+)"
)

# Authorization headers.
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")

# URI credentials (scheme://user:password@host): mask the password only.
_URI_CREDENTIAL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]*@")


def redact_for_cloud(text: str) -> str:
    """Mask known secret values in `text`, preserving key names and structure.

    Returns the original string unchanged when there is nothing to mask.
    """
    if not text:
        return text
    out = text
    for pat, label in _SECRET_VALUE_RULES:
        out = pat.sub(f"[REDACTED:{label}]", out)
    out = _KEY_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", out)
    out = _BEARER_RE.sub(r"\1 ***", out)
    out = _URI_CREDENTIAL_RE.sub(r"\1[REDACTED:uri-password]@", out)
    return out


def get_redaction_fingerprint() -> str:
    """Return a deterministic SHA256 fingerprint of the redaction ruleset.

    Encapsulates the private regex internals (`_SECRET_VALUE_RULES`,
    `_KEY_VALUE_RE`, `_BEARER_RE`, `_URI_CREDENTIAL_RE`) so downstream callers
    never reach into them. If the ruleset changes shape, the fingerprint changes
    accordingly (issue #26).
    """
    hasher = hashlib.sha256()
    for pat, _label in _SECRET_VALUE_RULES:
        hasher.update(pat.pattern.encode("utf-8"))
    hasher.update(_KEY_VALUE_RE.pattern.encode("utf-8"))
    hasher.update(_BEARER_RE.pattern.encode("utf-8"))
    hasher.update(_URI_CREDENTIAL_RE.pattern.encode("utf-8"))
    return hasher.hexdigest()
