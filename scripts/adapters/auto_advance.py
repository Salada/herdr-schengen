"""Auto-Advance coordinator for the dialog trampoline (Sprint 1c, P0 blocker).

When the gatekeeper approves command A but the pane has already advanced to a
NEW permission dialog B before the injection lands (``INJECT_SKIP_CHANGED``),
the legacy path returned "dialog changed; re-polling" and left A PENDING
forever — stalling the orchestrator. This coordinator instead RE-PARSES the
live dialog, RE-EVALUATES it through the FULL evaluator, and — if safe —
injects the new command automatically (Auto-Advance).

Hard invariants (do not weaken):
  INV-AA-1/2: B is ALWAYS re-evaluated full-pipeline; it NEVER inherits A's
      is_safe/approver/decision_layer. Prior-approval inheritance is FORBIDDEN.
      B inherits A's cwd/scope/agent_id but re-derives origin (Origin.AGENT).
  INV-AA-3: at most MAX_AUTO_ADVANCE_HOPS chained advances per action; the
      dialog found at the budget boundary (the MAX-th new dialog) is returned
      as ``budget_exhausted`` WITHOUT injection so the caller escalates it —
      the loop never auto-approves more than MAX_AUTO_ADVANCE_HOPS - 1 chained
      commands (fail-closed boundary).
  INV-AA-4: the whole action is capped by AUTO_ADVANCE_DEADLINE_SECONDS; on
      expiry the caller escalates (fail-closed).
  INV-AA-5: get_pending_request -> None / evaluator exception / unparseable ->
      ``parse_failed`` with fail-closed is_safe=False (the caller escalates).
  INV-AA-6: the coordinator never seeds session memory (novelty gate) and
      never calls workspace ``promote_rule``; recording provenance
      (approver="machine", mechanism="auto-advance") is the caller's job.
  INV-AA-9 (layering): this coordinator MAY import both the adapters and the
      evaluator, but the adapter layer must NEVER import the evaluator and the
      evaluator must NEVER import the adapters.

Pure orchestration — no subprocesses, no pane/key injection beyond the
adapter's own channel_approve/inject_approval verified-inject contract.
"""

import os
import re
import time
from dataclasses import dataclass
from typing import Optional

from adapters.agent_adapters import INJECT_SKIP_CHANGED, get_adapter
from adapters.herdr_client import get_pane_text
from core.security_evaluator import DecisionLayer, Origin, audit_shell_command_with_taxonomy

# At most this many chained auto-advance hops per action (INV-AA-3).
MAX_AUTO_ADVANCE_HOPS = int(os.environ.get("SCHENGEN_AUTO_ADVANCE_MAX_HOPS", "3"))
# Absolute wall-clock cap for the whole auto-advance action (INV-AA-4).
AUTO_ADVANCE_DEADLINE_SECONDS = float(os.environ.get("SCHENGEN_AUTO_ADVANCE_DEADLINE_SECONDS", "10.0"))


def _norm_req_cmd(s) -> str:
    """Canonicalize a request-command for equality comparison.

    Mirrors ``adapters.agent_adapters.opencode._norm_req_cmd`` EXACTLY: strip a
    leading '$ ' prompt and collapse whitespace ONLY. Deliberately NOT
    ``normalize_command`` — it collapses security-relevant fields (paths,
    quoted payloads, hashes, versions) to placeholders, which would weaken the
    trampoline guard and approve a DIFFERENT command (issue #23/#1910).
    """
    s = (s or "").strip()
    s = re.sub(r"^\$\s+", "", s)
    return re.sub(r"\s+", " ", s)


@dataclass
class AutoAdvanceResult:
    """Terminal result of one auto-advance action.

    outcome: "not_trampolined" | "advanced_safe" | "advanced_unsafe"
             | "budget_exhausted" | "parse_failed"
    new_req_cmd: the NEW dialog command B (None when no new dialog was found).
    is_safe: the evaluator verdict for B (None when B was never evaluated).
    layer / taxonomy: the ACTUAL evaluator DecisionLayer + 2D taxonomy for B —
        never inherited from the prior command (INV-AA-1).
    """

    outcome: str
    new_req_cmd: Optional[str] = None
    is_safe: Optional[bool] = None
    reason: str = ""
    layer: Optional[DecisionLayer] = None
    taxonomy: Optional[dict] = None


def auto_advance_once(
    pane_id,
    agent_kind,
    prev_req_cmd,
    *,
    cwd,
    scope,
    agent_id,
    use_llm_judge,
    reasoning_effort,
    remaining_hops,
    deadline,
) -> AutoAdvanceResult:
    """Single re-parse + full re-evaluation of the live dialog (one hop).

    ``remaining_hops`` / ``deadline`` are carried for the run loop's budget
    context (the single hop itself does not spend them — run_auto_advance
    owns the budget). Returns ``not_trampolined`` when the dialog did NOT
    change (or is gone) so the caller re-delegates normally; otherwise the
    fresh full-pipeline verdict for the new dialog B.
    """
    try:
        text = get_pane_text(pane_id, lines=80)
    except Exception as exc:
        # INV-AA-5: pane read failure -> fail-closed.
        return AutoAdvanceResult(outcome="parse_failed", is_safe=False, reason=f"pane read failed (fail-closed): {exc}")

    adapter = get_adapter(agent_kind)
    if adapter is None:
        return AutoAdvanceResult(
            outcome="parse_failed", is_safe=False,
            reason=f"no adapter registered for agent kind {agent_kind!r}",
        )

    try:
        new_req = adapter.get_pending_request(pane_id, text)
    except Exception as exc:
        # INV-AA-5: re-parse failure -> fail-closed.
        return AutoAdvanceResult(outcome="parse_failed", is_safe=False, reason=f"dialog re-parse failed (fail-closed): {exc}")

    if new_req is None:
        return AutoAdvanceResult(outcome="not_trampolined", is_safe=False, reason="no pending request in live pane text")

    if _norm_req_cmd(new_req) == _norm_req_cmd(prev_req_cmd):
        # The live dialog still shows the SAME request A — not a trampoline.
        return AutoAdvanceResult(
            outcome="not_trampolined", new_req_cmd=new_req, is_safe=False,
            reason="live dialog still shows the same request; not trampolined",
        )

    # INV-AA-1/2: FULL evaluator, fresh verdict — B never inherits A's
    # approval. Origin is re-derived as AGENT (never inherited).
    try:
        is_safe, reason, layer, tax = audit_shell_command_with_taxonomy(
            new_req,
            use_llm_judge=use_llm_judge,
            reasoning_effort=reasoning_effort,
            origin=Origin.AGENT,
            cwd=cwd,
            scope=scope,
            agent_id=agent_id,
        )
    except Exception as exc:
        # INV-AA-5: evaluator exception -> fail-closed (treat as unsafe).
        return AutoAdvanceResult(
            outcome="parse_failed", is_safe=False, new_req_cmd=new_req,
            reason=f"evaluator exception (fail-closed): {exc}",
        )

    return AutoAdvanceResult(
        outcome="advanced_safe" if is_safe else "advanced_unsafe",
        new_req_cmd=new_req,
        is_safe=is_safe,
        reason=reason,
        layer=layer,
        taxonomy=tax,
    )


def _inject_safe_command(adapter, pane_id, req_cmd):
    """Verified-inject path for an auto-advanced safe command B.

    Returns (injected: bool, skip_changed: bool, reason: str). Mirrors the
    verified-inject contract of the watcher/gatekeeper: channel approve first
    (opencode permission.reply), then the adapter's keystroke inject_approval.
    skip_changed=True means the dialog trampolined AGAIN before the inject
    landed — the caller re-evaluates the next dialog instead of claiming a
    delivery.
    """
    if adapter is None:
        return False, False, "no adapter"
    try:
        ch_approved, ch_reason = adapter.channel_approve(pane_id, req_cmd)
        if ch_approved:
            return True, False, "channel approve delivered"
        if ch_reason == INJECT_SKIP_CHANGED:
            return False, True, "dialog trampolined again before channel approve"
        ok, inject_reason = adapter.inject_approval(pane_id, req_cmd)
        if ok:
            return True, False, "keystroke inject delivered"
        if inject_reason == INJECT_SKIP_CHANGED:
            return False, True, "dialog trampolined again before keystroke inject"
        return False, False, inject_reason or "inject failed"
    except Exception as exc:
        return False, False, f"inject exception (fail-closed): {exc}"


def run_auto_advance(
    pane_id,
    agent_kind,
    prev_req_cmd,
    *,
    cwd,
    scope,
    agent_id,
    use_llm_judge=False,
    reasoning_effort="low",
) -> AutoAdvanceResult:
    """Bounded auto-advance loop (INV-AA-3/4). Returns the terminal result.

    Each hop re-parses the live dialog and re-evaluates it through the FULL
    evaluator. A new SAFE dialog is auto-injected (channel approve then
    keystroke inject) while the hop budget remains, and the loop re-evaluates
    the NEXT dialog if it trampolines again. Fail-closed boundary: the dialog
    found at the budget boundary (the MAX-th new dialog) is returned as
    ``budget_exhausted`` WITHOUT injection so the caller escalates it; the
    absolute deadline caps the whole action (``budget_exhausted`` on expiry).
    """
    adapter = get_adapter(agent_kind)
    deadline = time.monotonic() + AUTO_ADVANCE_DEADLINE_SECONDS
    hops_remaining = max(1, MAX_AUTO_ADVANCE_HOPS)
    prev = prev_req_cmd
    last_safe = None

    while True:
        if time.monotonic() >= deadline:
            return AutoAdvanceResult(
                outcome="budget_exhausted", is_safe=False,
                new_req_cmd=last_safe.new_req_cmd if last_safe else None,
                reason="auto-advance deadline exceeded; escalating (fail-closed)",
                layer=last_safe.layer if last_safe else None,
                taxonomy=last_safe.taxonomy if last_safe else None,
            )

        result = auto_advance_once(
            pane_id, agent_kind, prev,
            cwd=cwd, scope=scope, agent_id=agent_id,
            use_llm_judge=use_llm_judge, reasoning_effort=reasoning_effort,
            remaining_hops=hops_remaining, deadline=deadline,
        )

        if result.outcome != "advanced_safe":
            # Chain completed quietly after >=1 injection -> the terminal result
            # is the last successfully injected dialog.
            if result.outcome == "not_trampolined" and last_safe is not None:
                return last_safe
            return result

        # A slow evaluator may have crossed the deadline mid-evaluation
        # (INV-AA-4): never inject past the deadline.
        if time.monotonic() >= deadline:
            return AutoAdvanceResult(
                outcome="budget_exhausted", is_safe=False, new_req_cmd=result.new_req_cmd,
                reason="auto-advance deadline exceeded during evaluation; escalating (fail-closed)",
                layer=result.layer, taxonomy=result.taxonomy,
            )

        # INV-AA-3 fail-closed boundary: never inject the MAX-th new dialog —
        # escalate it so the caller enqueues it for human review.
        if hops_remaining <= 1:
            return AutoAdvanceResult(
                outcome="budget_exhausted", is_safe=False, new_req_cmd=result.new_req_cmd,
                reason="auto-advance hop budget exhausted; escalating new dialog (fail-closed)",
                layer=result.layer, taxonomy=result.taxonomy,
            )

        injected, skip_changed, inj_reason = _inject_safe_command(adapter, pane_id, result.new_req_cmd)
        if skip_changed:
            # The dialog trampolined AGAIN before the inject landed; re-evaluate
            # the NEXT dialog. The hop was consumed evaluating this one
            # (fail-closed: budget bounds re-evaluations, never spins).
            hops_remaining -= 1
            prev = result.new_req_cmd
            continue
        if not injected:
            return AutoAdvanceResult(
                outcome="advanced_unsafe", is_safe=False, new_req_cmd=result.new_req_cmd,
                reason=f"auto-advance inject failed for new dialog: {inj_reason}",
                layer=result.layer, taxonomy=result.taxonomy,
            )

        last_safe = result
        hops_remaining -= 1
        prev = result.new_req_cmd
