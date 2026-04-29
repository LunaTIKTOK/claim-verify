from __future__ import annotations

from typing import Any

from gate import requires_secrets
from governance_service import evaluate_request, execute, issue_governance_token
from runtime_governance import RuntimeState


DOMAIN_RULES = {
    "finance": {"forbidden": ["gravity", "mass", "velocity", "force"]},
    "physics": {"forbidden": ["portfolio", "yield", "asset"]},
}


def detect_domain_mismatch(intent_text: str, domain: str) -> list[str]:
    rule = DOMAIN_RULES.get(domain.lower())
    if not rule:
        return []
    text = intent_text.lower()
    violations: list[str] = []
    for term in rule["forbidden"]:
        if term in text:
            violations.append(term)
            continue
        if term.endswith("y") and term[:-1] in text:
            violations.append(term)
    return violations


def intercept_and_execute(intent: dict, actor_context: dict) -> dict[str, Any]:
    intent_name = str(intent.get("intent") or intent.get("intent_text") or "")
    intent_text = str(intent.get("intent_text") or intent_name)
    tool_name = str(intent.get("tool_name") or actor_context.get("tool_id") or "")
    tool_args = dict(intent.get("tool_args") or {})
    domain = str(intent.get("domain") or "")

    current_state = RuntimeState[str(actor_context.get("current_state", RuntimeState.RESEARCH.value))]
    requested_next_state = RuntimeState[str(actor_context.get("requested_next_state", RuntimeState.READ_ONLY.value))]
    eval_decision = evaluate_request(
        intent=intent_name,
        tool_name=tool_name,
        actor_context=actor_context,
        tool_args=tool_args,
        current_state=current_state,
        requested_next_state=requested_next_state,
    )
    if eval_decision.status == "DENY":
        reason = eval_decision.correction_requirement.required_action if eval_decision.correction_requirement else "governance evaluation denied"
        return {"decision": "BLOCK", "executed": False, "reason": reason, "violations": None, "epistemic_status": None}

    issuance = issue_governance_token(intent_name, actor_context, tool_name, tool_args)
    if issuance.get("decision") != "ALLOW" or issuance.get("token") is None:
        return {"decision": "BLOCK", "executed": False, "reason": str(issuance.get("reason") or "governance denied"), "violations": None, "epistemic_status": None}

    violations = detect_domain_mismatch(intent_text, domain)
    if violations:
        return {
            "decision": "BLOCK",
            "executed": False,
            "reason": "DOMAIN_MISMATCH",
            "violations": violations,
            "epistemic_status": "UNSTABLE",
        }

    if requires_secrets(tool_name) and not bool(issuance.get("allow_secrets", False)):
        return {
            "decision": "BLOCK",
            "executed": False,
            "reason": "secret access denied",
            "violations": ["SECRET_ACCESS_DENIED"],
            "epistemic_status": None,
        }

    result = execute(intent_name, actor_context, issuance, tool_name, tool_args)
    if result.get("decision") == "BLOCK":
        return {
            "decision": "BLOCK",
            "executed": False,
            "reason": str(result.get("reason")),
            "violations": None,
            "epistemic_status": None,
        }
    return {"decision": "ALLOW", "executed": bool(result.get("executed", False)), "reason": None, "violations": None, "epistemic_status": None}
