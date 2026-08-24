"""Context-Full Session Cache Module for Herdr Schengen (SmartGate).

Computes deterministic SHA256 cache keys across execution dimensions:
SHA256(raw_cmd + cwd + scope + agent_id + origin + ruleset_version)

Provides:
- In-memory LRU cache (<0.1ms latency)
- SQLite persistent cache backing across daemon restarts / SIGHUP reloads
- Cache hit/miss telemetry
"""

import hashlib
import json
from typing import Any, Optional

from guard_db import clear_in_memory_cache, get_cached_evaluation, set_cached_evaluation


def get_dynamic_ruleset_version() -> str:
    """Compute deterministic dynamic ruleset version from cryptographic hash of prompts, rules, and redaction."""
    import redaction
    from cloud_judge import DEFAULT_GUARD_LLM_MODEL, GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT
    from security_evaluator import CRITICAL_SHELL_PATTERNS, MINIMAL_INSPECTOR_SYSTEM_PROMPT

    hasher = hashlib.sha256()
    hasher.update(MINIMAL_INSPECTOR_SYSTEM_PROMPT.encode("utf-8"))
    hasher.update(GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT.encode("utf-8"))
    hasher.update(DEFAULT_GUARD_LLM_MODEL.encode("utf-8"))
    for pat, _desc in CRITICAL_SHELL_PATTERNS:
        hasher.update(pat.encode("utf-8"))
    for pat, _label in redaction._SECRET_VALUE_RULES:
        hasher.update(pat.pattern.encode("utf-8"))
    hasher.update(redaction._KEY_VALUE_RE.pattern.encode("utf-8"))
    hasher.update(redaction._BEARER_RE.pattern.encode("utf-8"))
    hasher.update(redaction._URI_CREDENTIAL_RE.pattern.encode("utf-8"))
    return f"dyn-{hasher.hexdigest()[:12]}"


def clear_session_cache():
    """Clear in-memory cache entries."""
    clear_in_memory_cache()


def compute_cache_key(
    raw_cmd: str,
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
    origin: str = "A",
    env_vars: Optional[dict[str, str]] = None,
    ruleset_version: Optional[str] = None,
) -> str:
    """Compute context-full SHA256 cache key for command evaluation."""
    effective_ver = ruleset_version if ruleset_version is not None else get_dynamic_ruleset_version()
    norm_cmd = raw_cmd.strip()
    norm_cwd = str(cwd).strip() if cwd else ""
    norm_scope = str(scope).strip() if scope else "default"
    norm_agent = str(agent_id).strip() if agent_id else "default"
    norm_origin = str(origin).strip() if origin else "A"

    env_repr = ""
    if env_vars:
        sorted_kvs = sorted(
            (k, str(v)) for k, v in env_vars.items() if k in ("SCHENGEN_SHADOW_MODE", "HERDR_ENV", "AI_AGENT")
        )
        env_repr = json.dumps(sorted_kvs)

    canonical = f"cmd={norm_cmd}|cwd={norm_cwd}|scope={norm_scope}|agent={norm_agent}|origin={norm_origin}|env={env_repr}|ver={effective_ver}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_cached_result(cache_key: str) -> Optional[dict[str, Any]]:
    """Lookup evaluation result from context cache."""
    return get_cached_evaluation(cache_key)


def store_cached_result(
    cache_key: str,
    raw_cmd: str,
    is_safe: bool,
    safety_reason: str,
    decision_layer: str,
    taxonomy: dict[str, Any],
    cwd: str = "",
    scope: str = "default",
    agent_id: str = "default",
    origin: str = "A",
    ruleset_version: Optional[str] = None,
    ttl_seconds: int = 3600,
):
    """Store evaluation result in context cache."""
    effective_ver = ruleset_version if ruleset_version is not None else get_dynamic_ruleset_version()
    set_cached_evaluation(
        cache_key=cache_key,
        raw_command=raw_cmd,
        is_safe=is_safe,
        safety_reason=safety_reason,
        decision_layer=decision_layer,
        taxonomy=taxonomy,
        cwd=cwd,
        scope=scope,
        agent_id=agent_id,
        origin=origin,
        ruleset_version=effective_ver,
        ttl_seconds=ttl_seconds,
    )
