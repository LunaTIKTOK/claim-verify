from __future__ import annotations

from typing import Any, Callable

from audit import AuditLogger
from authority import InMemoryUsedTokenStore
from identity import IdentityValidationError, build_identity_envelope, validate_identity_envelope
from mcp_executor import MCPGovernanceExecutor, PaymentGate, SecurityViolationError
from policy import decide_policy
from reputation import ReputationRecord, reputation_tier, update_reputation
from toxic_cost import price_toxic_tokens
from verify import evaluate_input


class GlassWingCore:
    """Untrusted proposer core. Direct execution is forbidden."""

    def run(self, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("UNAUTHORIZED_EXECUTION: direct core access is blocked by constitutional authority")


class _ConstitutionalAuthority:
    def __init__(self, *, secret: str, payment_gate: PaymentGate | None = None, audit_logger: AuditLogger | None = None) -> None:
        self._secret = secret
        self._payment_gate = payment_gate or PaymentGate(wallet_balances={"agent-default": 100.0})
        self._used_token_store = InMemoryUsedTokenStore()
        self._audit_logger = audit_logger
        self._reputation_record = ReputationRecord()
        self._core = GlassWingCore()
        self._tools: dict[str, Callable[[dict[str, Any]], Any]] = {}
        self._executor = MCPGovernanceExecutor(
            secret=self._secret,
            tools=self._tools,
            used_token_store=self._used_token_store,
            payment_gate=self._payment_gate,
            audit_logger=self._audit_logger,
        )

    def register_tool(self, tool_name: str, tool: Callable[[dict[str, Any]], Any]) -> None:
        self._tools[tool_name] = tool

    def blocked_core(self) -> GlassWingCore:
        return self._core

    def blocked_tool_executor(self) -> MCPGovernanceExecutor:
        return self._executor

    def _required_bond(self, toxic_multiplier: float) -> float:
        return round(max(5.0, toxic_multiplier * 5.0), 6)

    def _execute(self, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        agent_id = str(actor_context.get("agent_id", ""))
        policy_ids = [str(x) for x in actor_context.get("policy_ids", ["default-policy"])]

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

        verification_view = {
            "structural_validity": verification.get("structural_validity"),
            "confidence": verification.get("confidence", 0.0),
            "reasoning_risk": verification.get("reasoning_contamination_risk", "medium"),
            "fallback_used": fallback_used,
        }
        decision = decide_policy(
            verification=verification_view,
            toxic=toxic,
            identity_ok=True,
            reputation_tier=tier,
        )

        try:
            envelope = build_identity_envelope(
                action_name=tool_name,
                payload=tool_args,
                context=actor_context,
                policy_version="stage3",
                key_id="governance-hmac",
            )
            validate_identity_envelope(envelope)
        except IdentityValidationError as exc:
            raise RuntimeError(f"UNAUTHORIZED_EXECUTION: invalid actor identity ({exc})") from exc

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


_DEFAULT_AUTHORITY = _ConstitutionalAuthority(secret="dev-governance-secret")


def configure_authority(*, secret: str = "dev-governance-secret", payment_gate: PaymentGate | None = None, audit_logger: AuditLogger | None = None) -> None:
    global _DEFAULT_AUTHORITY
    _DEFAULT_AUTHORITY = _ConstitutionalAuthority(secret=secret, payment_gate=payment_gate, audit_logger=audit_logger)


def register_tool(tool_name: str, tool: Callable[[dict[str, Any]], Any]) -> None:
    _DEFAULT_AUTHORITY.register_tool(tool_name, tool)


def blocked_core_access() -> GlassWingCore:
    return _DEFAULT_AUTHORITY.blocked_core()


def blocked_tool_access() -> MCPGovernanceExecutor:
    return _DEFAULT_AUTHORITY.blocked_tool_executor()


def execute(intent: str, actor_context: dict, tool_name: str, tool_args: dict) -> dict[str, Any]:
    """The only public execution entry point. Non-bypassable authority boundary."""
    return _DEFAULT_AUTHORITY._execute(intent, actor_context, tool_name, tool_args)
