# Cognitive-firewall Threat Model

## Threats stopped

- Direct tool bypass attempts (public `gate.execute(...)` and `governance_service.execute(...)` are blocked).
- Token forgery and signature mismatch.
- Token replay after consumption/revocation.
- Payload tampering against token-bound payload hash.
- Domain mismatch at interceptor boundary.
- Unsupported speculation and contradictory evidence in uncertainty gate.
- Unauthorized secret access to secret-gated tools.
- Invalid state escalation denied by runtime governance transitions.

## Threats not stopped

- Compromised host machine.
- Leaked signing keys.
- Malicious maintainer changing source code and redeploying.
- External API calls made outside the interceptor/governed runtime path.
- Incorrect or unsafe policy definitions.

## Trust assumptions

- All consequential execution routes through `interceptor.intercept_and_execute(...)`.
- Signing keys are protected outside the model and rotated by operators.
- Tools are registered through the governed registry before invocation.

## Token/key assumptions

- Active key id and key material are consistent across issuance and verification.
- Governance tokens are short-lived and bound to intent/tool/payload hash.
- Token lifecycle stores preserve pending/used/revoked semantics.

## Execution boundary assumptions

- Public execution entrypoint is interceptor-only.
- Internal execution is reachable through `execute_authorized_from_interceptor(...)` only.
- Audit receipt generation remains enabled for forensic traceability.

## SPECULATE mode risk boundaries

- SPECULATE is bounded execution, not truth certification.
- Allocation cap checks happen before token issuance.
- Unsupported critical assumptions and contradictions are blocked.
- Falsification triggers are emitted for operator monitoring.
