"""Redacted, structured timing timelines for Gatekeeper escalations.

Only fixed metadata labels and numeric timings are accepted.  Commands, tool
arguments, tool output, model text, paths, and exception messages therefore
cannot enter this telemetry surface by construction.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional


TIMELINE_DIR = Path.home() / ".local" / "state" / "herdr-schengen" / "gatekeeper-timelines"
_EVENT_FIELDS = frozenset({
    "phase", "turn", "attempt", "tool", "status_code", "completion_state",
    "backoff_ms", "decision_layer",
})
_STAGES = frozenset({
    "detection", "deterministic_evaluation", "queue", "llm_attempt",
    "retry_backoff", "inspector_turn", "judge_turn", "tool_call",
    "terminal_delivery",
})
_EVENT_OUTCOMES = frozenset({
    "detected", "delegated", "enqueued", "success", "retry", "http_error",
    "network_error", "cancelled", "failed", "complete", "delivered",
    "dialog_changed",
})
_PHASES = frozenset({"Inspector", "Judge"})
_TOOLS = frozenset({
    "investigate_pane_history", "investigate_path_details", "read_file_snippet",
    "grep_search", "view_file_slice", "approve_escalation", "reject_escalation",
    "create_feature_request", "search_feature_requests",
})
_COMPLETION_STATES = frozenset({"complete", "truncated", "failed", "cancelled"})
_TERMINAL_OUTCOMES = frozenset({"approved", "rejected", "deferred", "cancelled", "delivery_failed"})
_TERMINAL_REASONS = frozenset({
    "gatekeeper_approved", "gatekeeper_rejected", "model_no_tool_call",
    "inspector_truncated", "inspector_api_failure", "judge_api_failure",
    "user_cancelled", "inspector_turn_limit", "approval_delivery_failed",
    "rejection_delivery_failed", "adjudication_delivery_failed",
    "adjudication_internal_error", "internal_error", "dialog_changed",
    "stale_dialog", "superseded", "tool_failure",
})
_DECISION_LAYERS = frozenset({
    "ALLOWLIST", "MANAGED_GIT_GUARD", "SAST_SHELLCHECK", "SAST_SEMGREP",
    "SHELL_CRITICAL", "SANDBOX_GUARD", "PYTHON_AST", "SECRET_GUARD",
    "LLM_INSPECTOR", "CLOUD_JUDGE", "GRAY_ZONE_MATRIX", "FAST_TRACK_AST",
    "NOT_ALLOWLISTED", "HUMAN_APPROVED", "PACKAGE_GUARD", "COMPLEXITY_TAX",
    "ORIGIN_GUARD", "NORMALIZATION_AMBIGUOUS", "FAST_TRACK_WORKSPACE_ALLOWLIST",
    "OPENCODE_FAILSAFE",
})


def _enum(value: Any, allowed: frozenset[str], default: str = "unknown") -> str:
    candidate = str(value or "")
    return candidate if candidate in allowed else default


def _non_negative_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


class GatekeeperTimeline:
    """One metadata-only JSON document for one persistent escalation."""

    def __init__(self, escalation_id: int, data: Optional[dict[str, Any]] = None):
        self.escalation_id = int(escalation_id)
        self.path = TIMELINE_DIR / f"escalation-{self.escalation_id}.json"
        self.data = data or self._fresh_data()
        self.loaded_from_disk = False

    def _fresh_data(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "correlation_id": uuid.uuid4().hex,
            "escalation_id": self.escalation_id,
            "decision_layer": "unknown",
            "decision_path": [],
            "events": [],
            "terminal": None,
        }

    @classmethod
    def _sanitized_data(cls, escalation_id: int, loaded: Any) -> Optional[dict[str, Any]]:
        if not isinstance(loaded, dict) or loaded.get("escalation_id") != escalation_id:
            return None
        correlation_id = str(loaded.get("correlation_id") or "")
        if len(correlation_id) != 32 or any(char not in "0123456789abcdef" for char in correlation_id):
            correlation_id = uuid.uuid4().hex
        clean = {
            "schema_version": 1,
            "correlation_id": correlation_id,
            "escalation_id": escalation_id,
            "decision_layer": _enum(loaded.get("decision_layer"), _DECISION_LAYERS),
            "decision_path": [],
            "events": [],
            "terminal": None,
        }
        for raw_event in loaded.get("events") or []:
            if not isinstance(raw_event, dict):
                continue
            start = _non_negative_int(raw_event.get("started_monotonic_ns"))
            finish = max(start, _non_negative_int(raw_event.get("finished_monotonic_ns")))
            event = {
                "sequence": len(clean["events"]) + 1,
                "stage": _enum(raw_event.get("stage"), _STAGES),
                "started_monotonic_ns": start,
                "finished_monotonic_ns": finish,
                "duration_ms": round((finish - start) / 1_000_000, 3),
                "outcome": _enum(raw_event.get("outcome"), _EVENT_OUTCOMES),
            }
            for key in _EVENT_FIELDS:
                value = raw_event.get(key)
                if value is None:
                    continue
                if key in {"turn", "attempt", "status_code", "backoff_ms"}:
                    event[key] = _non_negative_int(value)
                elif key == "phase":
                    event[key] = _enum(value, _PHASES)
                elif key == "tool":
                    event[key] = _enum(value, _TOOLS, "unknown_tool")
                elif key == "completion_state":
                    event[key] = _enum(value, _COMPLETION_STATES)
                elif key == "decision_layer":
                    event[key] = _enum(value, _DECISION_LAYERS)
            clean["events"].append(event)
        clean["events"].sort(key=lambda item: (item["started_monotonic_ns"], item["sequence"]))
        for sequence, event in enumerate(clean["events"], 1):
            event["sequence"] = sequence
        clean["decision_path"] = list(dict.fromkeys(event["stage"] for event in clean["events"]))
        terminal = loaded.get("terminal")
        if isinstance(terminal, dict):
            clean["terminal"] = {
                "at_monotonic_ns": _non_negative_int(terminal.get("at_monotonic_ns")),
                "outcome": _enum(terminal.get("outcome"), _TERMINAL_OUTCOMES),
                "reason": _enum(terminal.get("reason"), _TERMINAL_REASONS),
                "completion_state": _enum(terminal.get("completion_state"), _COMPLETION_STATES),
            }
        return clean

    @classmethod
    def load(cls, escalation_id: int) -> "GatekeeperTimeline":
        timeline = cls(escalation_id)
        try:
            loaded = json.loads(timeline.path.read_text(encoding="utf-8"))
            clean = cls._sanitized_data(int(escalation_id), loaded)
            if clean is not None:
                timeline.data = clean
                timeline.loaded_from_disk = True
        except Exception:
            pass
        return timeline

    @classmethod
    def begin(
        cls,
        escalation_id: int,
        *,
        decision_layer: Any,
        detected_ns: int,
        evaluation_started_ns: int,
        evaluation_finished_ns: int,
        queued_ns: Optional[int] = None,
        evaluation_outcome: str = "delegated",
        pre_events: Any = (),
    ) -> "GatekeeperTimeline":
        timeline = cls.load(escalation_id)
        fresh = timeline._fresh_data()
        fresh["decision_layer"] = _enum(decision_layer, _DECISION_LAYERS)

        def reset(data: dict[str, Any]) -> None:
            if data.get("events") and data.get("terminal") is None:
                data["decision_layer"] = fresh["decision_layer"]
            else:
                data.clear()
                data.update(fresh)

        timeline._mutate(reset)
        queued_ns = _non_negative_int(queued_ns or time.monotonic_ns())
        timeline.record(
            "detection",
            started_ns=detected_ns,
            finished_ns=evaluation_started_ns,
            outcome="detected",
        )
        timeline.record(
            "deterministic_evaluation",
            started_ns=evaluation_started_ns,
            finished_ns=evaluation_finished_ns,
            outcome=evaluation_outcome,
            decision_layer=decision_layer,
        )
        timeline.record(
            "queue",
            started_ns=evaluation_finished_ns,
            finished_ns=queued_ns,
            outcome="enqueued",
        )
        for event in pre_events if isinstance(pre_events, (list, tuple)) else ():
            if not isinstance(event, dict):
                continue
            timeline.record(
                event.get("stage", "unknown"),
                started_ns=event.get("started_ns"),
                finished_ns=event.get("finished_ns"),
                outcome=event.get("outcome", "unknown"),
                **{key: event[key] for key in _EVENT_FIELDS if key in event},
            )
        return timeline

    def record(
        self,
        stage: str,
        *,
        started_ns: Optional[int] = None,
        finished_ns: Optional[int] = None,
        outcome: str = "complete",
        **metadata: Any,
    ) -> None:
        def append(data: dict[str, Any]) -> None:
            now = time.monotonic_ns()
            start = _non_negative_int(started_ns if started_ns is not None else now)
            finish = _non_negative_int(finished_ns if finished_ns is not None else time.monotonic_ns())
            finish = max(start, finish)
            events = data.setdefault("events", [])
            safe_stage = _enum(stage, _STAGES)
            event = {
                "sequence": len(events) + 1,
                "stage": safe_stage,
                "started_monotonic_ns": start,
                "finished_monotonic_ns": finish,
                "duration_ms": round((finish - start) / 1_000_000, 3),
                "outcome": _enum(outcome, _EVENT_OUTCOMES),
            }
            for key, value in metadata.items():
                if key not in _EVENT_FIELDS or value is None:
                    continue
                if key in {"turn", "attempt", "status_code", "backoff_ms"}:
                    event[key] = _non_negative_int(value)
                elif key == "phase":
                    event[key] = _enum(value, _PHASES)
                elif key == "tool":
                    event[key] = _enum(value, _TOOLS, "unknown_tool")
                elif key == "completion_state":
                    event[key] = _enum(value, _COMPLETION_STATES)
                elif key == "decision_layer":
                    event[key] = _enum(value, _DECISION_LAYERS)
            events.append(event)
            events.sort(key=lambda item: (item["started_monotonic_ns"], item["sequence"]))
            for sequence, item in enumerate(events, 1):
                item["sequence"] = sequence
            data["decision_path"] = list(dict.fromkeys(item["stage"] for item in events))

        self._mutate(append)

    def finish(self, outcome: str, reason: str, completion_state: str) -> None:
        def set_terminal(data: dict[str, Any]) -> None:
            previous = data.get("terminal") or {}
            if previous.get("outcome") in {"approved", "rejected", "cancelled"}:
                return
            if previous.get("outcome") == "delivery_failed" and _enum(outcome, _TERMINAL_OUTCOMES) == "deferred":
                return
            data["terminal"] = {
                "at_monotonic_ns": time.monotonic_ns(),
                "outcome": _enum(outcome, _TERMINAL_OUTCOMES),
                "reason": _enum(reason, _TERMINAL_REASONS),
                "completion_state": _enum(completion_state, _COMPLETION_STATES),
            }

        self._mutate(set_terminal)

    def snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.data))

    def _mutate(self, mutate) -> None:
        tmp = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self.path.with_suffix(".lock")
            with lock_path.open("a", encoding="utf-8") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                try:
                    loaded = json.loads(self.path.read_text(encoding="utf-8"))
                    clean = self._sanitized_data(self.escalation_id, loaded)
                    if clean is not None:
                        self.data = clean
                except Exception:
                    pass
                mutate(self.data)
                tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
                tmp.write_text(
                    json.dumps(self.data, sort_keys=True, separators=(",", ":")),
                    encoding="utf-8",
                )
                os.replace(tmp, self.path)
        except Exception:
            try:
                if tmp is not None:
                    tmp.unlink(missing_ok=True)
            except Exception:
                pass
