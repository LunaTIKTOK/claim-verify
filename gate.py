from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from typing import Any, Callable

from audit import AuditLogger
from authority import UsedTokenStore, build_token, compute_payload_hash, create_used_token_store_from_env, serialize_token
from identity import IdentityValidationError, build_identity_envelope, validate_identity_envelope
from intent_classification import classify_intent
from mcp_executor import MCPGovernanceExecutor, PaymentGate, SecurityViolationError, create_payment_gate_from_env
from policy import decide_policy
from reputation import ReputationRecord, reputation_tier, update_reputation
from runtime_governance import RuntimeState, evaluate_runtime_governance
from toxic_cost import price_toxic_tokens
from verify import evaluate_input


class _GlassWingCore:
    """Untrusted proposer core. Direct execution is forbidden."""

    def run(self, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("UNAUTHORIZED_EXECUTION: direct core access is blocked by constitutional authority")


@dataclass
class KeyRing:
    active_key_id: str
    keys: dict[str, str]

    @classmethod
    def from_env(cls) -> "KeyRing":
        keys_json = os.environ.get("GOVERNANCE_KEYS_JSON")
        if keys_json:
            parsed = json.loads(keys_json)
            active = os.environ.get("GOVERNANCE_ACTIVE_KEY_ID", next(iter(parsed.keys())))
            if active not in parsed:
                raise RuntimeError("Configured active governance key id is missing from key ring")
            return cls(active_key_id=active, keys={str(k): str(v) for k, v in parsed.items()})

        env_secret = os.environ.get("GOVERNANCE_SECRET")
        env_key_id = os.environ.get("GOVERNANCE_KEY_ID", "dev-default-kid")
        if not env_secret:
            raise RuntimeError("GOVERNANCE_SECRET (or GOVERNANCE_KEYS_JSON) must be set")
        return cls(active_key_id=env_key_id, keys={env_key_id: env_secret})

    def resolve(self, key_id: str) -> str | None:
        return self.keys.get(key_id)


class _ConstitutionalAuthority:
    def __init__(
        self,
        *,
        key_ring: KeyRing,
        payment_gate: PaymentGate | None = None,
        used_token_store: UsedTokenStore | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._key_ring = key_ring
        self._payment_gate = payment_gate or create_payment_gate_from_env()
        self._used_token_store = used_token_store or create_used_token_store_from_env()
        self._audit_logger = audit_logger
        self._reputation_record = ReputationRecord()
        self._core = _GlassWingCore()
        self._tools: dict[str, Callable[[dict[str, Any]], Any]] = {}
        self._issuance_tickets: dict[str, str] = {}
        self._executor = MCPGovernanceExecutor(
            key_resolver=self._key_ring.resolve,
            tools=self._tools,
            used_token_store=self._used_token_store,
            payment_gate=self._payment_gate,
            audit_logger=self._audit_logger,
        )

    def register_tool(self, tool_name: str, tool: Callable[[dict[str, Any]], Any]) -> None:
        def _guarded_tool(args: dict[str, Any]) -> Any:
            if not bool(args.pop("__mcp_executor_call__", False)):
                raise RuntimeError("UNAUTHORIZED_EXECUTION: tools may only run through MCPGovernanceExecutor")
            return tool(args)

        self._tools[tool_name] = _guarded_tool

    def _ticket_fingerprint(self, *, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> str:
        current_state = str(actor_context.get("current_state", RuntimeState.RESEARCH.value))
        requested_next_state = str(actor_context.get("requested_next_state", RuntimeState.READ_ONLY.value))
        policy_ids = [str(x) for x in actor_context.get("policy_ids", ["default-policy"])]
        return "|".join(
            [
                str(actor_context.get("agent_id", "")),
                intent,
                tool_name,
                ",".join(policy_ids),
                current_state,
                requested_next_state,
                compute_payload_hash(tool_args),
            ]
        )

    def mint_issuance_ticket(self, *, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> str:
        ticket_id = secrets.token_urlsafe(24)
        self._issuance_tickets[ticket_id] = self._ticket_fingerprint(
            intent=intent,
            actor_context=actor_context,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        return ticket_id

    def consume_issuance_ticket(self, *, ticket_id: str, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> bool:
        expected_fingerprint = self._issuance_tickets.pop(ticket_id, None)
        if expected_fingerprint is None:
            return False
        actual_fingerprint = self._ticket_fingerprint(
            intent=intent,
            actor_context=actor_context,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        return expected_fingerprint == actual_fingerprint

    def _evaluate_issuance_governance(self, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]):
        current_state = RuntimeState[str(actor_context.get("current_state", RuntimeState.RESEARCH.value))]
        requested_next_state = RuntimeState[str(actor_context.get("requested_next_state", RuntimeState.READ_ONLY.value))]
        return evaluate_runtime_governance(
            current_state=current_state,
            requested_next_state=requested_next_state,
            tool_name=tool_name,
            intent_class=classify_intent(tool_name, intent),
            actor_identity_ok=bool(actor_context.get("agent_id")),
            approval_token_present=bool(actor_context.get("approval_token")),
            solvency_ok=bool(actor_context.get("solvency_ok", True)),
            reputation_tier=str(actor_context.get("reputation_tier", "TRUSTED")),
            soft_override_justification=actor_context.get("override_justification"),
            context=tool_args,
            policy_pack_paths=[
                "packs/financial_pack.json",
                "packs/privacy_pack.json",
                "packs/brand_pack.json",
                "packs/system_pack.json",
            ],
        )

    def issue_governance_token(self, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> str:
        issuance_ticket = actor_context.get("governance_issuance_ticket")
        if not isinstance(issuance_ticket, str) or not issuance_ticket:
            raise RuntimeError("UNAUTHORIZED_EXECUTION: missing governance issuance ticket")
        if not self.consume_issuance_ticket(
            ticket_id=issuance_ticket,
            intent=intent,
            actor_context=actor_context,
            tool_name=tool_name,
            tool_args=tool_args,
        ):
            raise RuntimeError("UNAUTHORIZED_EXECUTION: invalid governance issuance ticket")

        governance_decision = self._evaluate_issuance_governance(intent, actor_context, tool_name, tool_args)
        if governance_decision.status == "DENY":
            reason = governance_decision.correction_requirement.required_action if governance_decision.correction_requirement else "GOVERNANCE_DENY"
            raise RuntimeError(f"UNAUTHORIZED_EXECUTION: governance denied token issuance ({reason})")

        agent_id = str(actor_context.get("agent_id", ""))
        policy_ids = [str(x) for x in actor_context.get("policy_ids", ["default-policy"])]
        key_id = self._key_ring.active_key_id
        secret = self._key_ring.resolve(key_id)
        if secret is None:
            raise RuntimeError("UNAUTHORIZED_EXECUTION: active key secret is unavailable")

        token = build_token(
            key_id=key_id,
            agent_id=agent_id,
            intent=intent,
            tool_name=tool_name,
            policy_ids=policy_ids,
            payload_hash=compute_payload_hash(tool_args),
            secret=secret,
            ttl_seconds=int(actor_context.get("governance_token_ttl_seconds", 300)),
        )
        self._used_token_store.set_issued(token)
        return serialize_token(token)

    def _required_bond(self, toxic_multiplier: float) -> float:
        return round(max(5.0, toxic_multiplier * 5.0), 6)

    def _execute(self, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        agent_id = str(actor_context.get("agent_id", ""))
        policy_ids = [str(x) for x in actor_context.get("policy_ids", ["default-policy"])]

        identity_ok = True
        try:
            envelope = build_identity_envelope(
                action_name=tool_name,
                payload=tool_args,
                context=actor_context,
                policy_version="stage3",
                key_id=self._key_ring.active_key_id,
            )
            validate_identity_envelope(envelope)
        except IdentityValidationError:
            identity_ok = False

        claim_text = str(tool_args.get("claim") or intent)
        verification = evaluate_input(claim_text)
        warning_codes = list(verification.get("claim_graph_warnings") or [])
        fallback_used = bool(warning_codes)

        tier = reputation_tier(self._reputation_record)
        toxic = price_toxic_tokens(
            warning_codes=warning_codes,
            fallback_used=fallback_used,
            denial_history=self._reputation_record.denial_count,
            confidence=float(verification.get("confidence", 0.0)),
            evidence_strength=str(verification.get("evidence_strength", "none")),
            claim_graph_invalidity=fallback_used,
            retry_count=int(actor_context.get("retry_count", 0)),
            reputation_tier=tier,
        )

        decision = decide_policy(
            verification={
                "structural_validity": verification.get("structural_validity"),
                "confidence": verification.get("confidence", 0.0),
                "reasoning_risk": verification.get("reasoning_contamination_risk", "medium"),
                "fallback_used": fallback_used,
            },
            toxic=toxic,
            identity_ok=identity_ok,
            reputation_tier=tier,
        )

        if not identity_ok:
            raise RuntimeError("UNAUTHORIZED_EXECUTION: invalid actor identity")

        if decision in {"DENY", "REQUIRE_REAUTH"}:
            update_reputation(
                self._reputation_record,
                warning_codes=warning_codes,
                fallback_used=fallback_used,
                denied=True,
                retried=bool(actor_context.get("retry_count", 0)),
                invalid_signature=False,
                confidence=float(verification.get("confidence", 0.0)),
                degraded=True,
            )
            raise RuntimeError("UNAUTHORIZED_EXECUTION: policy denied execution")

        required_balance = self._required_bond(float(toxic.get("toxic_token_multiplier", 1.0)))
        if not self._payment_gate.ensure_solvency(agent_id, required_balance):
            raise RuntimeError("UNAUTHORIZED_EXECUTION: insufficient solvency for governance bond")
        if not self._payment_gate.lock_bond(agent_id, required_balance):
            raise RuntimeError("UNAUTHORIZED_EXECUTION: failed to lock governance bond")

        try:
            result = self._executor.execute(
                governance_token=actor_context.get("governance_token"),
                expected_key_id=self._key_ring.active_key_id,
                expected_agent_id=agent_id,
                expected_intent=intent,
                expected_tool_name=tool_name,
                expected_policy_ids=policy_ids,
                tool_args=tool_args,
            )
            self._payment_gate.release_bond(agent_id, required_balance)
        except SecurityViolationError:
            update_reputation(
                self._reputation_record,
                warning_codes=warning_codes,
                fallback_used=fallback_used,
                denied=True,
                retried=bool(actor_context.get("retry_count", 0)),
                invalid_signature=True,
                confidence=float(verification.get("confidence", 0.0)),
                degraded=True,
            )
            raise

        update_reputation(
            self._reputation_record,
            warning_codes=warning_codes,
            fallback_used=fallback_used,
            denied=False,
            retried=bool(actor_context.get("retry_count", 0)),
            invalid_signature=False,
            confidence=float(verification.get("confidence", 0.0)),
            degraded=decision == "ALLOW_WITH_CONSTRAINTS",
        )

        return {
            "decision": decision,
            "verification": verification,
            "toxic_cost": toxic,
            "constraints": list(toxic.get("required_constraints") or []),
            "executed": True,
            "result": result,
        }


_DEFAULT_AUTHORITY: _ConstitutionalAuthority | None = None


def _ensure_default_authority() -> _ConstitutionalAuthority:
    global _DEFAULT_AUTHORITY
    if _DEFAULT_AUTHORITY is None:
        _DEFAULT_AUTHORITY = _ConstitutionalAuthority(key_ring=KeyRing.from_env())
    return _DEFAULT_AUTHORITY


def configure_authority(
    *,
    key_ring: KeyRing,
    payment_gate: PaymentGate | None = None,
    used_token_store: UsedTokenStore | None = None,
    audit_logger: AuditLogger | None = None,
) -> None:
    global _DEFAULT_AUTHORITY
    _DEFAULT_AUTHORITY = _ConstitutionalAuthority(
        key_ring=key_ring,
        payment_gate=payment_gate,
        used_token_store=used_token_store,
        audit_logger=audit_logger,
    )


def register_tool(tool_name: str, tool: Callable[[dict[str, Any]], Any]) -> None:
    _ensure_default_authority().register_tool(tool_name, tool)


def mint_issuance_ticket(intent: str, actor_context: dict, tool_name: str, tool_args: dict) -> str:
    return _ensure_default_authority().mint_issuance_ticket(
        intent=intent,
        actor_context=actor_context,
        tool_name=tool_name,
        tool_args=tool_args,
    )


def issue_governance_token(intent: str, actor_context: dict, tool_name: str, tool_args: dict) -> str:
    return _ensure_default_authority().issue_governance_token(intent, actor_context, tool_name, tool_args)


def execute(intent: str, actor_context: dict, tool_name: str, tool_args: dict) -> dict[str, Any]:
    return _ensure_default_authority()._execute(intent, actor_context, tool_name, tool_args)


__all__ = ["configure_authority", "register_tool", "mint_issuance_ticket", "issue_governance_token", "execute"]
