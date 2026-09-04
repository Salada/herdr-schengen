"""Deterministic parsing for explicit human approval directives."""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class HumanDirective:
    action: str
    escalation_id: Optional[int]
    feedback: str
    source: str


_SLASH_RE = re.compile(r"^/(approve|reject)(?:\s+(\d+))?(?:\s+(.+))?$", re.IGNORECASE)
_APPROVE_PHRASES = frozenset(
    {
        "approve",
        "approve it",
        "approve it that's fine",
        "allow",
        "allow it",
        "proceed",
        "go ahead",
        "run it",
        "yes",
        "yes do it",
        "승인",
        "승인해",
        "승인해줘",
        "승인해주세요",
        "승인하라",
        "승인하세요",
        "진행",
        "진행해",
        "진행해줘",
        "진행해주세요",
        "진행하라",
        "진행하세요",
        "진행하자",
        "실행",
        "실행해",
        "실행해줘",
        "실행해주세요",
        "허용",
        "허용해",
        "허용해주세요",
    }
)
_REJECT_PHRASES = frozenset(
    {
        "reject",
        "reject it",
        "block",
        "block it",
        "stop",
        "do not run it",
        "don't run it",
        "no",
        "거절",
        "거절해",
        "거절해줘",
        "거절해주세요",
        "차단",
        "차단해",
        "차단해주세요",
        "중단",
        "중단해",
        "취소",
        "취소해",
        "실행하지마",
        "실행하지 마",
        "승인하지마",
        "승인하지 마",
    }
)


def _normalize_phrase(text: str) -> str:
    text = re.sub(r"[.!。！]+$", "", (text or "").strip().casefold())
    text = re.sub(r"[,，]\s*", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_human_directive(text: str, active_escalation_id: Optional[int] = None) -> Optional[HumanDirective]:
    """Return only unambiguous approve/reject intent; ordinary chat stays None.

    Free text is deliberately a closed set of complete utterances.  In
    particular, ``전체 승인`` is not interpreted as queue-wide or persistent
    authority; those scopes require explicit ``/approve-batch`` or
    ``/allow-url`` commands.
    """
    stripped = (text or "").strip()
    slash = _SLASH_RE.fullmatch(stripped)
    if slash:
        action = slash.group(1).lower()
        escalation_id = int(slash.group(2)) if slash.group(2) else active_escalation_id
        feedback = slash.group(3) or f"{action.title()}d via deterministic TUI directive"
        return HumanDirective(action, escalation_id, feedback, "slash")

    phrase = _normalize_phrase(stripped)
    if phrase in _APPROVE_PHRASES:
        return HumanDirective("approve", active_escalation_id, stripped, "free-text")
    if phrase in _REJECT_PHRASES:
        return HumanDirective("reject", active_escalation_id, stripped, "free-text")
    return None
