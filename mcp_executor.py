from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from audit import AuditLogger
from authority import UsedTokenStore, compute_payload_hash, deserialize_token, validate_token


class SecurityViolationError(RuntimeError):
    def __init__(self, reason: str, *, retry_tax_usd: float, bond_forfeited_usd: float, token_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_tax_usd = retry_tax_usd
        self.bond_forfeited_usd = bond_forfeited_usd
        self.token_id = token_id


class PaymentLedger(Protocol):
    def ensure_solvency(self, agent_id: str, required_balance_usd: float) -> bool:
        ...

    def lock_bond(self, agent_id: str, amount_usd: float) -> bool:
        ...

    def release_bond(self, agent_id: str, amount_usd: float) -> None:
        ...

    def forfeit_bond(self, agent_id: str, amount_usd: float) -> float:
        ...


@dataclass
class PaymentGate(PaymentLedger):
    treasury_usd: float = 0.0
    wallet_balances: dict[str, float] = None  # type: ignore[assignment]
    locked_bonds: dict[str, float] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.wallet_balances is None:
            self.wallet_balances = {}
        if self.locked_bonds is None:
            self.locked_bonds = {}
        self._lock = threading.Lock()

    def ensure_solvency(self, agent_id: str, required_balance_usd: float) -> bool:
        with self._lock:
            return self.wallet_balances.get(agent_id, 0.0) >= required_balance_usd

    def lock_bond(self, agent_id: str, amount_usd: float) -> bool:
        with self._lock:
            balance = self.wallet_balances.get(agent_id, 0.0)
            if balance < amount_usd:
                return False
            self.wallet_balances[agent_id] = round(balance - amount_usd, 6)
            self.locked_bonds[agent_id] = round(self.locked_bonds.get(agent_id, 0.0) + amount_usd, 6)
            return True

    def release_bond(self, agent_id: str, amount_usd: float) -> None:
        with self._lock:
            locked = self.locked_bonds.get(agent_id, 0.0)
            amount = min(locked, amount_usd)
            self.locked_bonds[agent_id] = round(locked - amount, 6)
            self.wallet_balances[agent_id] = round(self.wallet_balances.get(agent_id, 0.0) + amount, 6)

    def forfeit_bond(self, agent_id: str, amount_usd: float) -> float:
        with self._lock:
            locked = self.locked_bonds.get(agent_id, 0.0)
            forfeited = min(locked, amount_usd)
            self.locked_bonds[agent_id] = round(locked - forfeited, 6)
            self.treasury_usd = round(self.treasury_usd + forfeited, 6)
            return round(forfeited, 6)


class SQLitePaymentGate(PaymentLedger):
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS balances(agent_id TEXT PRIMARY KEY, balance REAL NOT NULL, locked REAL NOT NULL)"
            )
            conn.execute("CREATE TABLE IF NOT EXISTS treasury(id INTEGER PRIMARY KEY CHECK(id=1), amount REAL NOT NULL)")
            conn.execute("INSERT OR IGNORE INTO treasury(id, amount) VALUES(1, 0.0)")
            conn.commit()

    def seed_balance(self, agent_id: str, balance: float) -> None:
        with self._lock, sqlite3.connect(self._path) as conn:
            conn.execute(
                "INSERT INTO balances(agent_id,balance,locked) VALUES(?,?,0.0) ON CONFLICT(agent_id) DO UPDATE SET balance=excluded.balance",
                (agent_id, balance),
            )
            conn.commit()

    def ensure_solvency(self, agent_id: str, required_balance_usd: float) -> bool:
        with self._lock, sqlite3.connect(self._path) as conn:
            row = conn.execute("SELECT balance FROM balances WHERE agent_id = ?", (agent_id,)).fetchone()
            return bool(row and float(row[0]) >= required_balance_usd)

    def lock_bond(self, agent_id: str, amount_usd: float) -> bool:
        with self._lock, sqlite3.connect(self._path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT balance, locked FROM balances WHERE agent_id = ?", (agent_id,)).fetchone()
            if not row or float(row[0]) < amount_usd:
                conn.rollback()
                return False
            conn.execute("UPDATE balances SET balance = ?, locked = ? WHERE agent_id = ?", (float(row[0]) - amount_usd, float(row[1]) + amount_usd, agent_id))
            conn.commit()
            return True

    def release_bond(self, agent_id: str, amount_usd: float) -> None:
        with self._lock, sqlite3.connect(self._path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT balance, locked FROM balances WHERE agent_id = ?", (agent_id,)).fetchone()
            if not row:
                conn.rollback()
                return
            locked = float(row[1])
            amount = min(locked, amount_usd)
            conn.execute("UPDATE balances SET balance = ?, locked = ? WHERE agent_id = ?", (float(row[0]) + amount, locked - amount, agent_id))
            conn.commit()

    def forfeit_bond(self, agent_id: str, amount_usd: float) -> float:
        with self._lock, sqlite3.connect(self._path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT locked FROM balances WHERE agent_id = ?", (agent_id,)).fetchone()
            if not row:
                conn.rollback()
                return 0.0
            locked = float(row[0])
            forfeited = min(locked, amount_usd)
            conn.execute("UPDATE balances SET locked = ? WHERE agent_id = ?", (locked - forfeited, agent_id))
            treasury = conn.execute("SELECT amount FROM treasury WHERE id=1").fetchone()
            conn.execute("UPDATE treasury SET amount = ? WHERE id=1", (float(treasury[0]) + forfeited if treasury else forfeited,))
            conn.commit()
            return round(forfeited, 6)


def create_payment_gate_from_env() -> PaymentLedger:
    backend = os.environ.get("PAYMENT_GATE_BACKEND", "memory").lower()
    if backend == "sqlite":
        gate = SQLitePaymentGate(os.environ.get("PAYMENT_GATE_SQLITE_PATH", "payment_gate.db"))
        seed_json = os.environ.get("PAYMENT_GATE_SEED_BALANCES_JSON", "{}")
        for agent_id, balance in dict(__import__('json').loads(seed_json)).items():
            gate.seed_balance(str(agent_id), float(balance))
        return gate
    return PaymentGate(wallet_balances={})


class MCPGovernanceExecutor:
    def __init__(
        self,
        *,
        key_resolver: Callable[[str], str | None],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
        used_token_store: UsedTokenStore,
        payment_gate: PaymentLedger,
        audit_logger: AuditLogger | None,
    ) -> None:
        self._key_resolver = key_resolver
        self._tools = tools
        self._used_token_store = used_token_store
        self._payment_gate = payment_gate
        self._audit_logger = audit_logger

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
        correlation_id: str | None,
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
                "correlation_id": correlation_id,
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
        correlation_id: str | None,
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
            correlation_id=correlation_id,
        )
        raise SecurityViolationError(reason, retry_tax_usd=retry_tax_usd, bond_forfeited_usd=forfeited, token_id=token_id)

    def execute(
        self,
        *,
        governance_token: str | None,
        expected_key_id: str,
        expected_agent_id: str,
        expected_intent: str,
        expected_tool_name: str,
        expected_policy_ids: list[str],
        tool_args: dict[str, Any],
        correlation_id: str | None = None,
    ) -> Any:
        if not governance_token:
            self._apply_penalty_and_raise(
                reason="MISSING_GOVERNANCE_TOKEN",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=None,
                correlation_id=correlation_id,
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
                correlation_id=correlation_id,
            )
            raise  # pragma: no cover

        secret = self._key_resolver(token.key_id)
        if secret is None:
            self._apply_penalty_and_raise(
                reason="UNKNOWN_KEY_ID",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=token.token_id,
                correlation_id=correlation_id,
            )

        payload_hash = compute_payload_hash(tool_args)
        is_valid = validate_token(
            token,
            secret,
            expected_agent_id,
            expected_tool_name,
            self._used_token_store,
            expected_key_id=expected_key_id,
            expected_payload_hash=payload_hash,
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
                correlation_id=correlation_id,
            )

        if not self._used_token_store.mark_pending(token.token_id):
            self._apply_penalty_and_raise(
                reason="TOKEN_NOT_ISSUED_OR_ALREADY_USED",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=token.token_id,
                correlation_id=correlation_id,
            )

        tool = self._tools.get(expected_tool_name)
        if tool is None:
            self._used_token_store.mark_revoked(token.token_id)
            self._apply_penalty_and_raise(
                reason="UNKNOWN_TOOL",
                agent_id=expected_agent_id,
                intent=expected_intent,
                tool_name=expected_tool_name,
                policy_ids=expected_policy_ids,
                token_id=token.token_id,
                correlation_id=correlation_id,
            )

        guarded_args = dict(tool_args)
        guarded_args["__mcp_executor_call__"] = True
        try:
            result = tool(guarded_args)
        except Exception:
            self._used_token_store.mark_revoked(token.token_id)
            raise

        self._used_token_store.mark_consumed(token.token_id)
        return result
