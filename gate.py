from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from audit import AuditLogger
from authority import UsedTokenStore, build_token, compute_payload_hash, create_used_token_store_from_env, deserialize_token, serialize_token
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


VALID_STATES = {"RESEARCH", "READ_ONLY", "TRANSACTION", "PRIVILEGED", "HUMAN_REVIEW", "QUARANTINED"}
SECRET_FIELD_TOKENS = ("secret", "password", "token", "api_key", "credential", "auth")


def requires_secrets(tool_name: str) -> bool:
    lower = tool_name.lower()
    return any(token in lower for token in ("secret", "vault", "credential", "kms", "token"))


def has_secret_fields(tool_args: dict[str, Any]) -> bool:
    return any(any(token in key.lower() for token in SECRET_FIELD_TOKENS) for key in tool_args.keys())


def redact_secret_fields(tool_args: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(tool_args)
    for key in list(redacted.keys()):
        if any(token in key.lower() for token in SECRET_FIELD_TOKENS):
            redacted[key] = "[REDACTED]"
    return redacted


class GovernanceStateStore:
    def get_agent_state(self, agent_id: str) -> str:
        raise NotImplementedError

    def set_agent_state(self, agent_id: str, state: str) -> None:
        raise NotImplementedError

    def set_token_next_state(self, token_id: str, next_state: str) -> None:
        raise NotImplementedError

    def pop_token_next_state(self, token_id: str, default_state: str) -> str:
        raise NotImplementedError


class InMemoryGovernanceStateStore(GovernanceStateStore):
    def __init__(self) -> None:
        self._agent_states: dict[str, str] = {}
        self._token_next_state: dict[str, str] = {}

    def get_agent_state(self, agent_id: str) -> str:
        return self._agent_states.get(agent_id, "RESEARCH")

    def set_agent_state(self, agent_id: str, state: str) -> None:
        self._agent_states[agent_id] = state

    def set_token_next_state(self, token_id: str, next_state: str) -> None:
        self._token_next_state[token_id] = next_state

    def pop_token_next_state(self, token_id: str, default_state: str) -> str:
        return self._token_next_state.pop(token_id, default_state)


class SQLiteGovernanceStateStore(GovernanceStateStore):
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        with sqlite3.connect(self._path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS agent_state(agent_id TEXT PRIMARY KEY, state TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS token_state(token_id TEXT PRIMARY KEY, next_state TEXT NOT NULL)")
            conn.commit()

    def get_agent_state(self, agent_id: str) -> str:
        with self._lock, sqlite3.connect(self._path) as conn:
            row = conn.execute("SELECT state FROM agent_state WHERE agent_id = ?", (agent_id,)).fetchone()
            return str(row[0]) if row else "RESEARCH"

    def set_agent_state(self, agent_id: str, state: str) -> None:
        with self._lock, sqlite3.connect(self._path) as conn:
            conn.execute(
                "INSERT INTO agent_state(agent_id, state) VALUES(?, ?) ON CONFLICT(agent_id) DO UPDATE SET state=excluded.state",
                (agent_id, state),
            )
            conn.commit()

    def set_token_next_state(self, token_id: str, next_state: str) -> None:
        with self._lock, sqlite3.connect(self._path) as conn:
            conn.execute(
                "INSERT INTO token_state(token_id, next_state) VALUES(?, ?) ON CONFLICT(token_id) DO UPDATE SET next_state=excluded.next_state",
                (token_id, next_state),
            )
            conn.commit()

    def pop_token_next_state(self, token_id: str, default_state: str) -> str:
        with self._lock, sqlite3.connect(self._path) as conn:
            row = conn.execute("SELECT next_state FROM token_state WHERE token_id = ?", (token_id,)).fetchone()
            conn.execute("DELETE FROM token_state WHERE token_id = ?", (token_id,))
            conn.commit()
            return str(row[0]) if row else default_state


def create_governance_state_store_from_env() -> GovernanceStateStore:
    backend = os.environ.get("GOVERNANCE_STATE_BACKEND", "memory").lower()
    if backend == "sqlite":
        return SQLiteGovernanceStateStore(os.environ.get("GOVERNANCE_STATE_SQLITE_PATH", "governance_state.db"))
    return InMemoryGovernanceStateStore()


def _next_state_for_intent(intent: str) -> str:
    lower = intent.lower()
    if any(k in lower for k in ("trade", "payment", "transfer", "transaction")):
        return "TRANSACTION"
    if any(k in lower for k in ("privileged", "admin", "elevat", "root")):
        return "PRIVILEGED"
    if any(k in lower for k in ("quarantine", "unsafe")):
        return "QUARANTINED"
    return "READ_ONLY"


def is_valid_transition(current_state: str, intent: str) -> bool:
    next_state = _next_state_for_intent(intent)
    if current_state == "RESEARCH" and next_state == "TRANSACTION":
        return False
    if current_state == "READ_ONLY" and next_state == "TRANSACTION":
        return False
    if current_state == "TRANSACTION" and next_state == "PRIVILEGED":
        return False
    return True


def _transition_decision(current_state: str, intent: str) -> tuple[bool, str, str | None]:
    next_state = _next_state_for_intent(intent)
    if current_state not in VALID_STATES:
        return False, current_state, f"invalid current state: {current_state}"
    if current_state == "TRANSACTION" and next_state == "PRIVILEGED":
        return False, "HUMAN_REVIEW", "transition requires human review"
    if not is_valid_transition(current_state, intent):
        return False, current_state, f"invalid transition {current_state} -> {next_state}"
    return True, next_state, None


class _ConstitutionalAuthority:
    def __init__(
        self,
        *,
        key_ring: KeyRing,
        payment_gate: PaymentGate | None = None,
        used_token_store: UsedTokenStore | None = None,
        audit_logger: AuditLogger | None = None,
        governance_state_store: GovernanceStateStore | None = None,
    ) -> None:
        self._key_ring = key_ring
        self._payment_gate = payment_gate or create_payment_gate_from_env()
        self._used_token_store = used_token_store or create_used_token_store_from_env()
        self._audit_logger = audit_logger
        self._reputation_record = ReputationRecord()
        self._core = _GlassWingCore()
        self._tools: dict[str, Callable[[dict[str, Any]], Any]] = {}
        self._issuance_tickets: dict[str, str] = {}
        self._governance_state_store = governance_state_store or create_governance_state_store_from_env()
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

    def issue_governance_token(self, intent: str, actor_context: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        correlation_id = str(actor_context.get("correlation_id", uuid.uuid4().hex))
        actor_context["correlation_id"] = correlation_id
        agent_id = str(actor_context.get("agent_id", ""))
        current_state = self._governance_state_store.get_agent_state(agent_id)
        transition_ok, next_state, transition_reason = _transition_decision(current_state, intent)
        allow_secrets = bool(actor_context.get("allow_secrets", not requires_secrets(tool_name)))

        if not transition_ok:
            return {
                "decision": "BLOCK",
                "allow_secrets": allow_secrets,
                "token": None,
                "reason": transition_reason,
                "next_state": next_state,
                "correlation_id": correlation_id,
            }

        issuance_ticket = actor_context.get("governance_issuance_ticket")
        if not isinstance(issuance_ticket, str) or not issuance_ticket:
            return {
                "decision": "BLOCK",
                "allow_secrets": allow_secrets,
                "token": None,
                "reason": "missing governance ticket",
                "next_state": next_state,
                "correlation_id": correlation_id,
            }
        if not self.consume_issuance_ticket(
            ticket_id=issuance_ticket,
            intent=intent,
            actor_context=actor_context,
            tool_name=tool_name,
            tool_args=tool_args,
        ):
            return {
                "decision": "BLOCK",
                "allow_secrets": allow_secrets,
                "token": None,
                "reason": "invalid governance ticket",
                "next_state": next_state,
                "correlation_id": correlation_id,
            }

        governance_decision = self._evaluate_issuance_governance(intent, actor_context, tool_name, tool_args)
        if governance_decision.status == "DENY":
            reason = governance_decision.correction_requirement.required_action if governance_decision.correction_requirement else "GOVERNANCE_DENY"
            return {
                "decision": "BLOCK",
                "allow_secrets": allow_secrets,
                "token": None,
                "reason": f"governance denied token issuance ({reason})",
                "next_state": next_state,
                "correlation_id": correlation_id,
            }

        policy_ids = [str(x) for x in actor_context.get("policy_ids", ["default-policy"])]
        key_id = self._key_ring.active_key_id
        secret = self._key_ring.resolve(key_id)
        if secret is None:
            return {
                "decision": "BLOCK",
                "allow_secrets": allow_secrets,
                "token": None,
                "reason": "active key secret is unavailable",
                "next_state": next_state,
                "correlation_id": correlation_id,
            }

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
        self._governance_state_store.set_token_next_state(token.token_id, next_state)
        response = {
            "decision": "ALLOW",
            "allow_secrets": allow_secrets,
            "token": serialize_token(token),
            "reason": None,
            "next_state": next_state,
            "correlation_id": correlation_id,
        }
        if self._audit_logger:
            self._audit_logger.log(
                "GOVERNANCE_ISSUANCE",
                {
                    "correlation_id": correlation_id,
                    "agent_id": agent_id,
                    "intent": intent,
                    "tool_name": tool_name,
                    "next_state": next_state,
                },
            )
        return response

    def _required_bond(self, toxic_multiplier: float) -> float:
        return round(max(5.0, toxic_multiplier * 5.0), 6)

    def _execute(self, intent: str, actor_context: dict[str, Any], governance_decision: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        correlation_id = str((governance_decision or {}).get("correlation_id") or actor_context.get("correlation_id") or uuid.uuid4().hex)
        actor_context["correlation_id"] = correlation_id
        agent_id = str(actor_context.get("agent_id", ""))
        policy_ids = [str(x) for x in actor_context.get("policy_ids", ["default-policy"])]
        if not isinstance(governance_decision, dict):
            return {
                "decision": "BLOCK",
                "allow_secrets": False,
                "token": None,
                "reason": "missing governance_decision",
                "next_state": None,
                "correlation_id": correlation_id,
                "executed": False,
            }
        token = governance_decision.get("token")
        issuance_decision = str(governance_decision.get("decision", "BLOCK"))
        if issuance_decision != "ALLOW" or token is None:
            return {
                "decision": "BLOCK",
                "allow_secrets": bool(governance_decision.get("allow_secrets", False)),
                "token": token,
                "reason": "governance decision is BLOCK or token is missing",
                "next_state": governance_decision.get("next_state"),
                "correlation_id": correlation_id,
                "executed": False,
            }

        try:
            token_obj = deserialize_token(str(token))
        except Exception:
            return {
                "decision": "BLOCK",
                "allow_secrets": bool(governance_decision.get("allow_secrets", False)),
                "token": token,
                "reason": "invalid governance token serialization",
                "next_state": governance_decision.get("next_state"),
                "correlation_id": correlation_id,
                "executed": False,
            }
        payload_hash = compute_payload_hash(tool_args)
        if token_obj.tool_name != tool_name or token_obj.intent != intent or token_obj.payload_hash != payload_hash:
            return {
                "decision": "BLOCK",
                "allow_secrets": bool(governance_decision.get("allow_secrets", False)),
                "token": token,
                "reason": "token-context mismatch",
                "next_state": governance_decision.get("next_state"),
                "correlation_id": correlation_id,
                "executed": False,
            }

        current_state = self._governance_state_store.get_agent_state(agent_id)
        transition_ok, next_state, transition_reason = _transition_decision(current_state, intent)
        allow_secrets = bool(governance_decision.get("allow_secrets", False))

        if issuance_decision != "ALLOW" or not transition_ok:
            return {
                "decision": "BLOCK",
                "allow_secrets": allow_secrets,
                "token": token,
                "reason": transition_reason or "governance decision is BLOCK",
                "next_state": next_state,
                "correlation_id": correlation_id,
                "executed": False,
            }

        if has_secret_fields(tool_args) and not allow_secrets:
            return {
                "decision": "BLOCK",
                "allow_secrets": False,
                "token": token,
                "reason": "tool arguments contain secret-bearing fields while allow_secrets is false",
                "next_state": next_state,
                "correlation_id": correlation_id,
                "executed": False,
            }
        if requires_secrets(tool_name) and not allow_secrets:
            return {
                "decision": "BLOCK",
                "allow_secrets": False,
                "token": token,
                "reason": "tool requires secrets but allow_secrets is false",
                "next_state": next_state,
                "correlation_id": correlation_id,
                "executed": False,
            }

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
                governance_token=str(token),
                expected_key_id=self._key_ring.active_key_id,
                expected_agent_id=agent_id,
                expected_intent=intent,
                expected_tool_name=tool_name,
                expected_policy_ids=policy_ids,
                tool_args=tool_args,
                correlation_id=correlation_id,
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
        self._governance_state_store.set_agent_state(
            agent_id,
            self._governance_state_store.pop_token_next_state(token_obj.token_id, next_state),
        )
        if self._audit_logger:
            self._audit_logger.log(
                "GOVERNANCE_EXECUTION",
                {
                    "correlation_id": correlation_id,
                    "agent_id": agent_id,
                    "intent": intent,
                    "tool_name": tool_name,
                    "executed": True,
                },
            )

        return {
            "decision": decision,
            "allow_secrets": allow_secrets,
            "token": token,
            "verification": verification,
            "toxic_cost": toxic,
            "constraints": list(toxic.get("required_constraints") or []),
            "executed": True,
            "result": result,
            "reason": None,
            "next_state": next_state,
            "correlation_id": correlation_id,
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
    governance_state_store: GovernanceStateStore | None = None,
) -> None:
    global _DEFAULT_AUTHORITY
    _DEFAULT_AUTHORITY = _ConstitutionalAuthority(
        key_ring=key_ring,
        payment_gate=payment_gate,
        used_token_store=used_token_store,
        audit_logger=audit_logger,
        governance_state_store=governance_state_store,
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


def issue_governance_token(intent: str, actor_context: dict, tool_name: str, tool_args: dict) -> dict[str, Any]:
    return _ensure_default_authority().issue_governance_token(intent, actor_context, tool_name, tool_args)


def execute(intent: str, actor_context: dict, governance_decision: dict[str, Any], tool_name: str, tool_args: dict) -> dict[str, Any]:
    return _ensure_default_authority()._execute(intent, actor_context, governance_decision, tool_name, tool_args)


__all__ = [
    "configure_authority",
    "register_tool",
    "mint_issuance_ticket",
    "issue_governance_token",
    "execute",
    "InMemoryGovernanceStateStore",
    "SQLiteGovernanceStateStore",
]
