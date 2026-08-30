"""OpenAI-compatible cloud judge client for Herdr Schengen (SmartGate).

Encapsulates LLM configuration resolution, HTTP transport, and verdict parsing
so `security_evaluator.py` stays focused on static/deterministic evaluation and
the judgment orchestration. Any OpenAI-compatible endpoint (OpenAI, vLLM,
Ollama, LocalAI, OpenRouter, or DeepSeek via OPENAI_BASE_URL) is a drop-in.
"""

import http.client
import json
import os
import random
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Optional

DEFAULT_GUARD_LLM_MODEL = os.environ.get("GUARD_LLM_MODEL", "gpt-5.6-luna")
DEFAULT_GUARD_LLM_ENDPOINT = "https://api.openai.com/v1/chat/completions"
DEFAULT_REASONING_EFFORT = os.environ.get("GUARD_REASONING_EFFORT", "low")

GENERAL_CLOUD_JUDGE_SYSTEM_PROMPT = (
    "You are a strict but pragmatic security gatekeeper for Herdr SmartGate. "
    "Decide whether a command or permission request should be auto-approved or deferred to a human. "
    'Respond ONLY in JSON: {"is_safe": true|false, "confidence": <0.0-1.0>, "reason": "<concise explanation>"}. '
    "confidence is your calibrated certainty that the command is safe to AUTO-APPROVE (1.0 = certain). "
    "Emit confidence >= 0.9 ONLY when the command is clearly benign with no ambiguity, egress, or mutation risk. "
    "Emit confidence < 0.9 (or is_safe=false) whenever there is ANY doubt, ambiguity, destructive, or exfil risk."
    "Rules & Session Safe Patterns:\n"
    "- Auto-approve obviously-safe, read-only, query, or routine development operations (e.g. git status/log/diff/rev-parse, test suites, CLI query/list/search scripts, safe /tmp redirections).\n"
    "- In-session safe repetitive templates (such as search queries with changing keywords, or test executions) should be recognized and approved without unnecessary friction.\n"
    "- Block and defer if there is destructive deletion (rm -rf), secret exfiltration (.env, id_rsa, tokens), system root modification (/etc, /var, /System), or ambiguous/dangerous payloads -> is_safe false.\n"
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


def parse_json_verdict(content_str: str, prefix: str = "[Cloud Judge]") -> Optional[tuple[bool, Optional[float], str]]:
    """Parse the model's JSON verdict, tolerating ```json fences.

    Returns a 3-tuple (is_safe, confidence, reason) where confidence is the
    model's calibrated certainty (clamped to [0.0, 1.0]) or None when absent /
    unparseable. Returns None if the whole payload is unparseable."""
    try:
        clean = re.sub(r"^```json\s*", "", content_str.strip(), flags=re.IGNORECASE)
        clean = re.sub(r"\s*```$", "", clean)
        res = json.loads(clean)
        is_safe = bool(res.get("is_safe", False))
        conf = res.get("confidence")
        if conf is not None:
            try:
                conf = max(0.0, min(1.0, float(conf)))
            except (TypeError, ValueError):
                conf = None
        return is_safe, conf, f"{prefix} {res.get('reason', 'Judged')}"
    except Exception:
        return None


MAX_ADAPTIVE_RETRIES = 10
DEFAULT_SOCKET_TIMEOUT = 10.0
RETRYABLE_HTTP_STATUSES = {429, 500, 502, 503, 504}


def post_cloud_judge(
    messages,
    endpoint,
    model,
    api_key,
    reasoning_effort,
    tools=None,
    max_retries: int = MAX_ADAPTIVE_RETRIES,
    timeout: float = DEFAULT_SOCKET_TIMEOUT,
):
    """HTTP client with adaptive exponential retry (up to 10 attempts) for network/API errors."""
    req_body: dict[str, Any] = {
        "model": model,
        "temperature": 0.0,
        "max_tokens": 300,
        "messages": messages,
    }
    if tools:
        req_body["tools"] = tools
        req_body["tool_choice"] = "auto"
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

    last_err: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(endpoint, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in RETRYABLE_HTTP_STATUSES and attempt < max_retries:
                # Respect Retry-After header if provided
                retry_after_header = e.headers.get("Retry-After") if e.headers else None
                if retry_after_header and retry_after_header.isdigit():
                    sleep_sec = min(10.0, float(retry_after_header))
                else:
                    sleep_sec = min(5.0, 0.1 * (1.5 ** (attempt - 1))) + random.uniform(0, 0.05)
                time.sleep(sleep_sec)
                continue
            raise
        except (
            urllib.error.URLError,
            socket.timeout,
            TimeoutError,
            http.client.RemoteDisconnected,
            ConnectionResetError,
            ConnectionRefusedError,
        ) as e:
            last_err = e
            if attempt < max_retries:
                sleep_sec = min(5.0, 0.1 * (1.5 ** (attempt - 1))) + random.uniform(0, 0.05)
                time.sleep(sleep_sec)
                continue
            raise

    if last_err:
        raise last_err
    raise RuntimeError("Max retries exceeded without result")
