"""Monotonic evaluation for rendered and canonical permission requests."""

from adapters.request_match import same_request
import core.security_evaluator as security_evaluator


_CONCRETE_DANGER_LAYERS = frozenset(
    {
        "MANAGED_GIT_GUARD",
        "SAST_SHELLCHECK",
        "SAST_SEMGREP",
        "SHELL_CRITICAL",
        "SANDBOX_GUARD",
        "PYTHON_AST",
        "SECRET_GUARD",
        "LLM_INSPECTOR",
        "GRAY_ZONE_MATRIX",
        "PACKAGE_GUARD",
    }
)


def _with_provenance(result, capture_source, relation, *, raw_evaluated=True):
    safe, reason, layer, taxonomy = result
    taxonomy = dict(taxonomy)
    taxonomy.update(
        {
            "capture_source": capture_source,
            "normalization_relation": relation,
            "raw_capture_evaluated": raw_evaluated,
        }
    )
    return safe, reason, layer, taxonomy


def evaluate_capture_pair(
    raw_command,
    canonical_command,
    capture_source,
    *,
    use_llm_judge=False,
    reasoning_effort,
    origin=None,
    cwd="",
    scope="default",
    agent_id="default",
    audit_func=None,
):
    """Evaluate both representations; normalization can never hide danger."""
    origin = origin or security_evaluator.Origin.AGENT
    if not raw_command or not canonical_command:
        reason = "Normalization ambiguous: rendered or canonical request is unavailable"
        taxonomy = security_evaluator.derive_taxonomy(
            canonical_command or raw_command or "",
            security_evaluator.DecisionLayer.NORMALIZATION_AMBIGUOUS,
            False,
            reason,
            origin=origin,
        )
        return _with_provenance(
            (False, reason, security_evaluator.DecisionLayer.NORMALIZATION_AMBIGUOUS, taxonomy),
            capture_source,
            "unavailable",
            raw_evaluated=False,
        )

    kwargs = dict(
        use_llm_judge=use_llm_judge,
        reasoning_effort=reasoning_effort,
        origin=origin,
        cwd=cwd,
        scope=scope,
        agent_id=agent_id,
    )
    audit = audit_func or security_evaluator.audit_shell_command_with_taxonomy
    raw_result = audit(raw_command, **kwargs)
    canonical_result = (
        raw_result
        if raw_command == canonical_command
        else audit(canonical_command, **kwargs)
    )

    relation = "same" if same_request(canonical_command, raw_command) else "different"
    for label, result in (("rendered", raw_result), ("canonical", canonical_result)):
        safe, reason, layer, _ = result
        layer_value = layer.value if hasattr(layer, "value") else str(layer)
        if not safe and layer_value in _CONCRETE_DANGER_LAYERS:
            return _with_provenance(
                (False, f"{label} representation blocked: {reason}", layer, result[3]),
                capture_source,
                relation,
            )

    if relation != "same" or capture_source in ("visible-mismatch", "visible-unparsed"):
        reason = "Normalization ambiguous: rendered and canonical requests do not have the same identity"
        taxonomy = security_evaluator.derive_taxonomy(
            canonical_command,
            security_evaluator.DecisionLayer.NORMALIZATION_AMBIGUOUS,
            False,
            reason,
            origin=origin,
        )
        return _with_provenance(
            (False, reason, security_evaluator.DecisionLayer.NORMALIZATION_AMBIGUOUS, taxonomy),
            capture_source,
            relation,
        )

    return _with_provenance(canonical_result, capture_source, relation)
