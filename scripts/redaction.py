"""Partial redaction for cloud-judge calls (Phase 2).

Rule-scoped value masking that preserves key names and structure so the cloud
judge can still recognize "a secret is present here" and block, while never
shipping the plaintext secret to a third-party model.

Only a bounded set of secret *shapes* is masked (partial redaction, per-rule),
not a blanket transform. Identifiers, paths, and command structure are left
intact so the judge's safety decision is unaffected.
"""

import re

# (pattern, label) pairs. The value is masked; the label preserves the secret
# TYPE (api-key / aws-key / ...) so a judge can still decide "block: contains a key".
_SECRET_VALUE_RULES = [
    (re.compile(r"\b(sk-[A-Za-z0-9]{16,})"), "api-key"),
    (re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})"), "aws-key"),
    (re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,})"), "github-pat"),
    (re.compile(r"\b(AIza[A-Za-z0-9_-]{30,})"), "google-key"),
    (re.compile(r"\b(hf_[A-Za-z0-9]{20,})"), "hf-token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "private-key"),
]

# `KEY=value` / `KEY: value` assignments: keep the key NAME, mask the value.
_KEY_VALUE_RE = re.compile(
    r"(?i)\b(token|secret|password|passwd|api[_-]?key|api[_-]?secret|"
    r"client[_-]?secret|access[_-]?key|credential|auth[_-]?token)s?"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^'\"\s]+)"
)

# Authorization headers.
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")


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
    return out
