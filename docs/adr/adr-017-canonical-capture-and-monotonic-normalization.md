# ADR-017: Canonical Capture and Monotonic Normalization

- **Status**: Active
- **Date**: 2026-09-05

## Context

Terminal rendering can insert soft wraps or apparent whitespace that are not
part of a command. Treating rendered pane text as executable syntax caused
valid shell and Python commands to be misclassified, while reconstructing a
command too aggressively could instead widen permission.

ADR-016 made capture provenance and normalization ambiguity observable. This
record defines which representation authorizes execution and how alternate
representations may influence that decision.

## Decision

1. `recent-unwrapped` is the canonical pane capture for command authorization.
   Every evaluation records its capture source and the relation between raw and
   normalized text.
2. Normalization is monotonic: it may preserve or reduce permission, but must
   never turn a command into a more permissive authorization result. A
   semantics-affecting difference remains pending for deterministic or human
   adjudication.
3. Rendered captures are diagnostic evidence only. They cannot override a
   canonical command that was captured successfully.
4. LLM reconstruction is advisory. Any reconstructed command must re-enter all
   deterministic guards before it can authorize execution.

## Consequences

- Soft wrapping and display whitespace no longer become command semantics.
- Ambiguous normalization fails closed without discarding useful diagnostic
  context.
- A weak or mistaken LLM reconstruction cannot bypass denylist or deterministic
  policy layers.
- Capture and normalization decisions remain auditable under ADR-016.
