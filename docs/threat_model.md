# Cognitive-firewall Threat Model

## What Cognitive-firewall stops

- Direct public execution bypasses through `gate.execute(...)` or `governance_service.execute(...)`.
- Tool execution without governance evaluation, issuance ticket, and valid governance token.
- Token replay and token/payload/tool identity mismatches.
- Domain-mismatched intents that violate deterministic domain rules.
- Unsupported or contradictory speculative theses before allocation-bearing execution.
- Secret-gated tool access when `allow_secrets` is not granted.

## What Cognitive-firewall does not stop

- Bad outcomes from true but incomplete world models (unknown unknowns).
- Adversarial data poisoning that occurs outside runtime boundary controls.
- Human policy misconfiguration (e.g., permissive policy packs).
- Exogenous shocks that invalidate a previously valid thesis after execution.
- Economic losses within explicitly permitted speculative allocation caps.

## Trust assumptions

- Policy packs represent operator intent and are maintained correctly.
- Actor context (`agent_id`, session/runtime identifiers, approval token) is trustworthy at ingestion.
- Registered tool implementations are honest about side effects.
- Local persistence (SQLite/filesystem) is available and has integrity during runtime.

## Token/key assumptions

- Signing keys are protected and rotated by operators as needed.
- Active key selection is correct and consistent across issuance and verification.
- Token lifecycle store integrity is preserved (pending/used/revoked semantics).
- Governance tokens remain short-lived and bound to intent/tool/payload hash.

## Execution boundary assumptions

- Only `interceptor.intercept_and_execute(...)` is treated as public execution entrypoint.
- Internal execution is reachable only through `execute_authorized_from_interceptor(...)`.
- Audit logging remains enabled for operator forensics and incident review.

## SPECULATE mode risk boundaries

- `SPECULATE` is bounded execution, not truth validation.
- Allocation cap checks occur before token issuance.
- Unsupported critical assumptions and evidence contradictions are blocked.
- Falsification triggers are required outputs for speculative visibility.
- Execution still requires governance decision, token issuance, and internal authorized execution.
