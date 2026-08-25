"""OpenAI-compatible cloud judge client for Herdr Schengen (SmartGate).

Encapsulates LLM configuration resolution, HTTP transport, and verdict parsing
so `security_evaluator.py` stays focused on static/deterministic evaluation and
the judgment orchestration. Any OpenAI-compatible endpoint (OpenAI, vLLM,
Ollama, LocalAI, OpenRouter, or DeepSeek via OPENAI_BASE_URL) is a drop-in.
"""

import json
import os
import re
import urllib.request
from typing import Any, Optional

DEFAULT_GUARD_LLM_MODEL = os.environ.get("GUARD_LLM_MODEL", "gpt-5.6-luna")
DEFAULT_GUARD_LLM_ENDPOINT = "https://api.openai.com/v1/chat/completions"
DEFAULT_REASONING_EFFORT = os.environ.get("GUARD_REASONING_EFFORT", "low")

GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT = (
    "You are a strict but pragmatic security gatekeeper for Herdr SmartGate. "
    "Decide whether a command or permission request should be auto-approved or deferred to a human. "
    'Respond ONLY in JSON: {"is_safe": true|false, "reason": "<concise explanation>"}. '
    "Rules:\n"
    "- Auto-approve only obviously-safe, read-only, or routine development operations.\n"
    "- Any destructive, secret-access, system-mutation, or ambiguous action -> is_safe false.\n"
    "- If safety cannot be determined from the available context -> is_safe false (defer to human)."
)


def resolve_guard_llm_config(endpoint=None, model=None, api_key=None):
    """Resolve (endpoint, model, api_key) with documented precedence.

    model    : explicit arg -> GUARD_LLM_MODEL -> DEFAULT_GUARD_LLM_MODEL
    endpoint : explicit arg -> GUARD_LLM_ENDPOINT -> GUARD_LLM_BASE_URL + /chat/completions
               -> OPENAI_BASE_URL + /chat/completions -> DEFAULT_GUARD_LLM_ENDPOINT
    api_key  : explicit arg -> GUARD_LLM_API_KEY -> OPENAI_API_KEY

    POLICY (issue #33): OpenAI-standard env vars only. DEEPSEEK_API_KEY and the
    DeepSeek default endpoint are removed. To keep using DeepSeek, set
    OPENAI_BASE_URL=https://api.deepseek.com/v1 (and OPENAI_API_KEY=<deepseek key>).
    """
    effective_model = model or os.environ.get("GUARD_LLM_MODEL") or DEFAULT_GUARD_LLM_MODEL

    if api_key:
        effective_key = api_key
    elif os.environ.get("GUARD_LLM_API_KEY"):
        effective_key = os.environ["GUARD_LLM_API_KEY"]
    elif os.environ.get("OPENAI_API_KEY"):
        effective_key = os.environ["OPENAI_API_KEY"]
    else:
        effective_key = ""

    base_url = (
        os.environ.get("GUARD_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or ""
    ).strip().rstrip("/")
    env_endpoint = os.environ.get("GUARD_LLM_ENDPOINT", "").strip().rstrip("/")

    if endpoint:
        effective_endpoint = str(endpoint).rstrip("/")
    elif env_endpoint:
        effective_endpoint = env_endpoint
    elif base_url:
        effective_endpoint = base_url + "/chat/completions"
    elif effective_key:
        effective_endpoint = DEFAULT_GUARD_LLM_ENDPOINT
    else:
        effective_endpoint = ""
    return effective_endpoint, effective_model, effective_key


def parse_json_verdict(content_str: str, prefix: str = "[Cloud Judge]") -> Optional[tuple[bool, str]]:
    """Parse the model's JSON verdict, tolerating ```json fences. Returns None if unparseable."""
    try:
        clean = re.sub(r"^```json\s*", "", content_str.strip(), flags=re.IGNORECASE)
        clean = re.sub(r"\s*```$", "", clean)
        res = json.loads(clean)
        is_safe = bool(res.get("is_safe", False))
        reason = f"{prefix} {res.get('reason', 'Judged')}"
        return is_safe, reason
    except Exception:
        return None


def post_cloud_judge(messages, endpoint, model, api_key, reasoning_effort, tools=None):
    """Single HTTP round-trip to an OpenAI-compatible chat completions endpoint."""
    req_body: dict[str, Any] = {
        "model": model,
        "temperature": 0.0,
        "max_tokens": 300,
        "messages": messages,
    }
    if tools:
        req_body["tools"] = tools
        req_body["tool_choice"] = "auto"
    # Only inject reasoning_effort if explicitly configured and targeting a reasoning model
    if (
        reasoning_effort
        and reasoning_effort.lower() not in ("off", "none", "")
        and ("reason" in model.lower() or "gpt-oss" in model.lower() or "gpt-5" in model.lower())
    ):
        req_body["reasoning_effort"] = reasoning_effort.lower()

    payload = json.dumps(req_body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(endpoint, data=payload, headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)
