from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol


@dataclass(frozen=True)
class GovernanceToken:
    token_id: str
    agent_id: str
    intent: str
    tool_name: str
    policy_ids: list[str]
    issued_at: str
    expires_at: str
    nonce: str
    signature: str


class UsedTokenStore(Protocol):
    """Token replay store interface.

    In production this should be backed by a persistent system (DB/redis/kv)
    shared across workers/replicas so consumed tokens remain invalid after restarts.
    """

    def is_used(self, token_id: str) -> bool:
        ...

    def mark_used(self, token_id: str) -> None:
        ...


class InMemoryUsedTokenStore:
    """Default non-persistent replay store used for local/dev tests."""

    def __init__(self) -> None:
        self._used_ids: set[str] = set()

    def is_used(self, token_id: str) -> bool:
        return token_id in self._used_ids

    def mark_used(self, token_id: str) -> None:
        self._used_ids.add(token_id)


def _canonical_payload(token: GovernanceToken) -> str:
    payload = {
        "agent_id": token.agent_id,
        "expires_at": token.expires_at,
        "intent": token.intent,
        "issued_at": token.issued_at,
        "nonce": token.nonce,
        "policy_ids": list(token.policy_ids),
        "token_id": token.token_id,
        "tool_name": token.tool_name,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_token_payload(payload: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def build_token(
    *,
    agent_id: str,
    intent: str,
    tool_name: str,
    policy_ids: list[str],
    secret: str,
    ttl_seconds: int = 300,
    now: datetime | None = None,
) -> GovernanceToken:
    issued = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    expires = issued + timedelta(seconds=ttl_seconds)
    token = GovernanceToken(
        token_id=f"gtok_{uuid.uuid4().hex}",
        agent_id=agent_id,
        intent=intent,
        tool_name=tool_name,
        policy_ids=sorted(set(policy_ids)),
        issued_at=issued.isoformat(),
        expires_at=expires.isoformat(),
        nonce=uuid.uuid4().hex,
        signature="",
    )
    signature = sign_token_payload(_canonical_payload(token), secret)
    return GovernanceToken(**{**token.__dict__, "signature": signature})


def serialize_token(token: GovernanceToken) -> str:
    return json.dumps(token.__dict__, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def deserialize_token(token_str: str) -> GovernanceToken:
    data = json.loads(token_str)
    return GovernanceToken(
        token_id=str(data["token_id"]),
        agent_id=str(data["agent_id"]),
        intent=str(data["intent"]),
        tool_name=str(data["tool_name"]),
        policy_ids=[str(x) for x in data.get("policy_ids", [])],
        issued_at=str(data["issued_at"]),
        expires_at=str(data["expires_at"]),
        nonce=str(data["nonce"]),
        signature=str(data["signature"]),
    )


def _parse_iso8601(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp missing timezone")
    return parsed


def validate_token(
    token: GovernanceToken,
    secret: str,
    expected_agent_id: str,
    expected_tool_name: str,
    used_token_store: UsedTokenStore,
    *,
    expected_intent: str | None = None,
    expected_policy_ids: list[str] | None = None,
) -> bool:
    now = datetime.now(timezone.utc)
    issued = _parse_iso8601(token.issued_at)
    expires = _parse_iso8601(token.expires_at)

    if issued > now:
        return False
    if expires <= now:
        return False
    if used_token_store.is_used(token.token_id):
        return False
    if token.agent_id != expected_agent_id:
        return False
    if token.tool_name != expected_tool_name:
        return False
    if expected_intent is not None and token.intent != expected_intent:
        return False
    if expected_policy_ids is not None and sorted(set(token.policy_ids)) != sorted(set(expected_policy_ids)):
        return False

    expected_sig = sign_token_payload(_canonical_payload(token), secret)
    return hmac.compare_digest(expected_sig, token.signature)
