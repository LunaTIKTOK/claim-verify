from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from audit import AuditLogger
from authority import UsedTokenStore, deserialize_token, validate_token


class SecurityViolationError(RuntimeError):
    def __init__(self, reason: str, *, retry_tax_usd: float, bond_forfeited_usd: float, token_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_tax_usd = retry_tax_usd
        self.bond_forfeited_usd = bond_forfeited_usd
        self.token_id = token_id


@dataclass
class PaymentGate:
    treasury_usd: float = 0.0
    wallet_balances: dict[str, float] = None  # type: ignore[assignment]
    locked_bonds: dict[str, float] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.wallet_balances is None:
            self.wallet_balances = {}
        if self.locked_bonds is None:
            self.locked_bonds = {}

    def ensure_solvency(self, agent_id: str, required_balance_usd: float) -> bool:
        return self.wallet_balances.get(agent_id, 0.0) >= required_balance_usd

    def lock_bond(self, agent_id: str, amount_usd: float) -> bool:
        balance = self.wallet_balances.get(agent_id, 0.0)
        if balance < amount_usd:
            return False
        self.wallet_balances[agent_id] = round(balance - amount_usd, 6)
        self.locked_bonds[agent_id] = round(self.locked_bonds.get(agent_id, 0.0) + amount_usd, 6)
        return True

    def release_bond(self, agent_id: str, amount_usd: float) -> None:
        locked = self.locked_bonds.get(agent_id, 0.0)
        amount = min(locked, amount_usd)
        self.locked_bonds[agent_id] = round(locked - amount, 6)
        self.wallet_balances[agent_id] = round(self.wallet_balances.get(agent_id, 0.0) + amount, 6)

    def forfeit_bond(self, agent_id: str, amount_usd: float) -> float:
        locked = self.locked_bonds.get(agent_id, 0.0)
        forfeited = min(locked, amount_usd)
        self.locked_bonds[agent_id] = round(locked - forfeited, 6)
        self.treasury_usd = round(self.treasury_usd + forfeited, 6)
        return round(forfeited, 6)


class MCPGovernanceExecutor:
    def __init__(
        self,
        *,
        secret: str,
        tools: dict[str, Callable[[dict[str, Any]], Any]],
        used_token_store: UsedTokenStore,
        payment_gate: PaymentGate,
        audit_logger: AuditLogger | None,
    ) -> None:
        self._secret = secret
        self._tools = tools
        self._used_token_store = used_token_store
        self._payment_gate = payment_gate
        self._audit_logger = audit_logger

    def invoke_tool(self, _tool_name: str, _tool_args: dict[str, Any]) -> Any:
        raise RuntimeError("UNAUTHORIZED_EXECUTION: direct tool access is blocked by constitutional authority")

    def _log_violation(
        self,
        *,
        agent_id: str,
        intent: str,
        tool_name: str,
        policy_ids: list[str],
        reason: str,
        retry_tax_usd: float,
        bond_forfeited_usd: float,
        token_id: str | None,
    ) -> None:
        if not self._audit_logger:
            return
        self._audit_logger.log(
            "SECURITY_VIOLATION",
            {
                "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "agent_id": agent_id,
                "intent": intent,
                "tool_name": tool_name,
                "policy_ids": list(policy_ids),
                "reason": reason,
                "retry_tax_usd": round(retry_tax_usd, 6),
                "bond_forfeited_usd": round(bond_forfeited_usd, 6),
                "security_violation": True,
                "token_id": token_id,
            },
        )

    def _apply_penalty_and_raise(
        self,
        *,
        reason: str,
        agent_id: str,
        intent: str,
        tool_name: str,
        policy_ids: list[str],
        token_id: str | None,
        retry_tax_usd: float = 1.5,
        bond_penalty_usd: float = 5.0,
    ) -> None:
        forfeited = self._payment_gate.forfeit_bond(agent_id, bond_penalty_usd)
        self._log_violation(
            agent_id=agent_id,
            intent=intent,
            tool_name=tool_name,
            policy_ids=policy_ids,
            reason=reason,
            retry_tax_usd=retry_tax_usd,
            bond_forfeited_usd=forfeited,
            token_id=token_id,
        )
        raise SecurityViolationError(reason, retry_tax_usd=retry_tax_usd, bond_forfeited_usd=forfeited, token_id=token_id)

    def execute(
        self,
        *,
        governance_token: str | None,
        expected_agent_id: str,
        expected_intent: str,
        expected_tool_name: str,
        expected_policy_ids: list[str],
        tool_args: dict[str, Any],
    ) -> Any:
        if not governance_token:
            self._apply_penalty_and_raise(
                reason="MISSING_GOVERNANCE_TOKEN",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=None,
            )

        try:
            token = deserialize_token(governance_token)
        except Exception:
            self._apply_penalty_and_raise(
                reason="INVALID_TOKEN_SERIALIZATION",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=None,
            )
            raise  # pragma: no cover

        if self._used_token_store.is_used(token.token_id):
            self._apply_penalty_and_raise(
                reason="REPLAY_ATTACK",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=token.token_id,
                retry_tax_usd=2.25,
                bond_penalty_usd=7.5,
            )

        is_valid = validate_token(
            token,
            self._secret,
            expected_agent_id,
            expected_tool_name,
            self._used_token_store,
            expected_intent=expected_intent,
            expected_policy_ids=expected_policy_ids,
        )
        if not is_valid:
            self._apply_penalty_and_raise(
                reason="INVALID_GOVERNANCE_TOKEN",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=token.token_id,
            )

        tool = self._tools.get(expected_tool_name)
        if tool is None:
            self._apply_penalty_and_raise(
                reason="UNKNOWN_TOOL",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=token.token_id,
            )

        result = tool(dict(tool_args))
        self._used_token_store.mark_used(token.token_id)
        return result
