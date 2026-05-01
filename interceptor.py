from __future__ import annotations

from typing import Any

from gate import execute_authorized_from_interceptor, requires_secrets
from governance_service import evaluate_request, issue_governance_token
from runtime_governance import RuntimeState
from uncertainty_governance import Assumption, AssumptionMap, evaluate_uncertainty


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
    speculative = False
    confidence_average = None
    max_allocation_pct = None
    falsification_triggers = []

    violations = detect_domain_mismatch(intent_text, domain)
    if violations:
        return {
            "decision": "BLOCK",
            "executed": False,
            "reason": "DOMAIN_MISMATCH",
            "violations": violations,
            "epistemic_status": "UNSTABLE",
        }

    assumptions_raw = intent.get("assumptions")
    claim = str(intent.get("claim") or tool_args.get("claim") or intent_text)
    if assumptions_raw:
        assumptions = [
            Assumption(
                assumption=str(item.get("assumption") or ""),
                status=str(item.get("status") or ""),
                confidence=float(item.get("confidence") or 0.0),
                evidence=[str(e) for e in list(item.get("evidence") or [])],
                falsification_trigger=(str(item.get("falsification_trigger")) if item.get("falsification_trigger") is not None else None),
                critical=bool(item.get("critical", False)),
            )
            for item in assumptions_raw
        ]
        map_confidence = float(
            intent.get("confidence_average")
            or tool_args.get("confidence_average")
            or (sum(item.confidence for item in assumptions) / len(assumptions))
        )
        triggers = [item.falsification_trigger for item in assumptions if item.falsification_trigger]
        assumption_map = AssumptionMap(
            claim=claim,
            assumptions=assumptions,
            mode=str(intent.get("mode") or "INVESTING"),
            confidence_average=map_confidence,
            max_allocation_pct=float(intent.get("max_allocation_pct") or tool_args.get("max_allocation_pct") or 2.0),
            falsification_triggers=triggers,
        )
        uncertainty = evaluate_uncertainty(assumption_map)
        if uncertainty["decision"] == "BLOCK":
            return {
                "decision": "BLOCK",
                "executed": False,
                "reason": str(uncertainty["reason"]),
                "violations": None,
                "epistemic_status": "UNSTABLE",
                "speculative": False,
                "max_allocation_pct": uncertainty["max_allocation_pct"],
                "confidence_average": uncertainty["confidence_average"],
                "falsification_triggers": uncertainty["falsification_triggers"],
            }
        if uncertainty["decision"] == "SPECULATE":
            requested_allocation_pct = intent.get("requested_allocation_pct", tool_args.get("requested_allocation_pct"))
            if requested_allocation_pct is None or float(requested_allocation_pct) > float(uncertainty["max_allocation_pct"]):
                return {
                    "decision": "BLOCK",
                    "executed": False,
                    "reason": "SPECULATIVE_ALLOCATION_EXCEEDS_CAP",
                    "violations": None,
                    "epistemic_status": "UNSTABLE",
                    "speculative": True,
                    "max_allocation_pct": uncertainty["max_allocation_pct"],
                    "confidence_average": uncertainty["confidence_average"],
                    "falsification_triggers": uncertainty["falsification_triggers"],
                }
            speculative = True
        confidence_average = uncertainty["confidence_average"]
        max_allocation_pct = uncertainty["max_allocation_pct"]
        falsification_triggers = list(uncertainty["falsification_triggers"])

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
        return {"decision": "BLOCK", "executed": False, "reason": reason, "violations": None, "epistemic_status": None, "speculative": speculative, "max_allocation_pct": max_allocation_pct, "confidence_average": confidence_average, "falsification_triggers": falsification_triggers}

    issuance = issue_governance_token(intent_name, actor_context, tool_name, tool_args)
    if issuance.get("decision") != "ALLOW" or issuance.get("token") is None:
        return {"decision": "BLOCK", "executed": False, "reason": str(issuance.get("reason") or "governance denied"), "violations": None, "epistemic_status": None, "speculative": speculative, "max_allocation_pct": max_allocation_pct, "confidence_average": confidence_average, "falsification_triggers": falsification_triggers}

    if requires_secrets(tool_name) and not bool(issuance.get("allow_secrets", False)):
        return {
            "decision": "BLOCK",
            "executed": False,
            "reason": "secret access denied",
            "violations": ["SECRET_ACCESS_DENIED"],
            "epistemic_status": None,
            "speculative": speculative,
            "max_allocation_pct": max_allocation_pct,
            "confidence_average": confidence_average,
            "falsification_triggers": falsification_triggers,
        }

    result = execute_authorized_from_interceptor(intent_name, actor_context, issuance, tool_name, tool_args)
    if result.get("decision") == "BLOCK":
        return {
            "decision": "BLOCK",
            "executed": False,
            "reason": str(result.get("reason")),
            "violations": None,
            "epistemic_status": None,
            "speculative": speculative,
            "max_allocation_pct": max_allocation_pct,
            "confidence_average": confidence_average,
            "falsification_triggers": falsification_triggers,
        }
    return {
        "decision": "SPECULATE" if speculative else "ALLOW",
        "executed": bool(result.get("executed", False)),
        "reason": None,
        "violations": None,
        "epistemic_status": None,
        "speculative": speculative,
        "max_allocation_pct": max_allocation_pct,
        "confidence_average": confidence_average,
        "falsification_triggers": falsification_triggers,
    }
