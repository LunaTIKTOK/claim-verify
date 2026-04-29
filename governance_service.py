from __future__ import annotations

import uuid
from typing import Any

from gate import _execute_via_interceptor
from gate import issue_governance_token as _issue_governance_token
from gate import mint_issuance_ticket
from intent_classification import classify_intent
from runtime_governance import RuntimeState, evaluate_runtime_governance


DEFAULT_POLICY_PACKS = [
    "packs/financial_pack.json",
    "packs/privacy_pack.json",
    "packs/brand_pack.json",
    "packs/system_pack.json",
]


def evaluate_request(
    *,
    intent: str,
    tool_name: str,
    actor_context: dict[str, Any],
    tool_args: dict[str, Any],
    current_state: RuntimeState,
    requested_next_state: RuntimeState,
):
    actor_context["correlation_id"] = str(actor_context.get("correlation_id") or uuid.uuid4().hex)
    intent_class = classify_intent(tool_name, intent)
    decision = evaluate_runtime_governance(
        current_state=current_state,
        requested_next_state=requested_next_state,
        tool_name=tool_name,
        intent_class=intent_class,
        actor_identity_ok=bool(actor_context.get("agent_id")),
        approval_token_present=bool(actor_context.get("approval_token")),
        solvency_ok=bool(actor_context.get("solvency_ok", True)),
        reputation_tier=str(actor_context.get("reputation_tier", "TRUSTED")),
        soft_override_justification=actor_context.get("override_justification"),
        context=tool_args,
        policy_pack_paths=DEFAULT_POLICY_PACKS,
    )
    actor_context.pop("governance_issuance_ticket", None)
    if decision.status != "DENY":
        actor_context["governance_issuance_ticket"] = mint_issuance_ticket(
            intent=intent,
            actor_context=actor_context,
            tool_name=tool_name,
            tool_args=tool_args,
        )
    return decision


def issue_governance_token(intent: str, actor_context: dict, tool_name: str, tool_args: dict) -> dict[str, Any]:
    if not actor_context.get("governance_issuance_ticket"):
        response = {
            "decision": "BLOCK",
            "allow_secrets": False,
            "token": None,
            "reason": "evaluate_request must pass before token issuance",
            "next_state": str(actor_context.get("state", "RESEARCH")),
            "correlation_id": str(actor_context.get("correlation_id") or uuid.uuid4().hex),
        }
        actor_context["governance_decision"] = response
        return response
    response = _issue_governance_token(intent, actor_context, tool_name, tool_args)
    actor_context["governance_decision"] = response
    return response


def execute(intent: str, actor_context: dict, governance_decision: dict[str, Any], tool_name: str, tool_args: dict):
    return _execute_via_interceptor(intent, actor_context, governance_decision, tool_name, tool_args)
