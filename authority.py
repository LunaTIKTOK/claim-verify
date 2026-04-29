from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

TokenStatus = Literal["issued", "pending", "consumed", "expired", "revoked"]


@dataclass(frozen=True)
class GovernanceToken:
    token_id: str
    key_id: str
    agent_id: str
    intent: str
    tool_name: str
    policy_ids: list[str]
    payload_hash: str
    issued_at: str
    expires_at: str
    nonce: str
    signature: str


class UsedTokenStore(Protocol):
    """Replay/token lifecycle store interface.

    Production deployments should use a persistent shared implementation so
    token state is durable across restarts and horizontally scaled workers.
    """

    def get_status(self, token_id: str) -> TokenStatus | None:
        ...

    def set_issued(self, token: GovernanceToken) -> None:
        ...

    def mark_pending(self, token_id: str) -> bool:
        ...

    def mark_consumed(self, token_id: str) -> bool:
        ...

    def mark_revoked(self, token_id: str) -> bool:
        ...


class InMemoryUsedTokenStore:
    """Default non-persistent replay store used for local/dev tests."""

    def __init__(self) -> None:
        self._status: dict[str, TokenStatus] = {}
        self._expiry: dict[str, str] = {}
        self._lock = threading.Lock()

    def _is_expired(self, token_id: str) -> bool:
        exp = self._expiry.get(token_id)
        if not exp:
            return False
        parsed = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        return parsed <= datetime.now(timezone.utc)

    def get_status(self, token_id: str) -> TokenStatus | None:
        with self._lock:
            status = self._status.get(token_id)
            if status is None:
                return None
            if self._is_expired(token_id):
                self._status[token_id] = "expired"
                return "expired"
            return status

    def set_issued(self, token: GovernanceToken) -> None:
        with self._lock:
            self._status[token.token_id] = "issued"
            self._expiry[token.token_id] = token.expires_at

    def mark_pending(self, token_id: str) -> bool:
        with self._lock:
            status = self._status.get(token_id)
            if status is None:
                return False
            if self._is_expired(token_id):
                self._status[token_id] = "expired"
                return False
            if status != "issued":
                return False
            self._status[token_id] = "pending"
            return True

    def mark_consumed(self, token_id: str) -> bool:
        with self._lock:
            status = self._status.get(token_id)
            if status is None:
                return False
            if self._is_expired(token_id):
                self._status[token_id] = "expired"
                return False
            if status not in {"issued", "pending"}:
                return False
            self._status[token_id] = "consumed"
            return True

    def mark_revoked(self, token_id: str) -> bool:
        with self._lock:
            status = self._status.get(token_id)
            if status is None:
                return False
            if self._is_expired(token_id):
                self._status[token_id] = "expired"
                return False
            if status in {"consumed", "expired", "revoked"}:
                return False
            self._status[token_id] = "revoked"
            return True


class SQLiteUsedTokenStore:
    """Persistent token lifecycle store for production hardening."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS token_status (
                    token_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def _normalize_status(self, status: str, expires_at: str) -> TokenStatus:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry <= datetime.now(timezone.utc) and status not in {"consumed", "revoked"}:
            return "expired"
        return status  # type: ignore[return-value]

    def get_status(self, token_id: str) -> TokenStatus | None:
        with self._lock, sqlite3.connect(self._path) as conn:
            row = conn.execute("SELECT status, expires_at FROM token_status WHERE token_id = ?", (token_id,)).fetchone()
            if not row:
                return None
            status = self._normalize_status(str(row[0]), str(row[1]))
            if status == "expired":
                conn.execute(
                    "UPDATE token_status SET status = ?, updated_at = ? WHERE token_id = ?",
                    ("expired", self._now_iso(), token_id),
                )
                conn.commit()
            return status

    def set_issued(self, token: GovernanceToken) -> None:
        with self._lock, sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                INSERT INTO token_status(token_id, status, expires_at, updated_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(token_id) DO NOTHING
                """,
                (token.token_id, "issued", token.expires_at, self._now_iso()),
            )
            conn.commit()

    def _transition(self, token_id: str, from_statuses: set[str], to_status: TokenStatus) -> bool:
        with self._lock, sqlite3.connect(self._path) as conn:
            row = conn.execute("SELECT status, expires_at FROM token_status WHERE token_id = ?", (token_id,)).fetchone()
            if not row:
                return False
            current = self._normalize_status(str(row[0]), str(row[1]))
            if current not in from_statuses:
                return False
            conn.execute(
                "UPDATE token_status SET status = ?, updated_at = ? WHERE token_id = ?",
                (to_status, self._now_iso(), token_id),
            )
            conn.commit()
            return True

    def mark_pending(self, token_id: str) -> bool:
        return self._transition(token_id, {"issued"}, "pending")

    def mark_consumed(self, token_id: str) -> bool:
        return self._transition(token_id, {"issued", "pending"}, "consumed")

    def mark_revoked(self, token_id: str) -> bool:
        return self._transition(token_id, {"issued", "pending"}, "revoked")


def create_used_token_store_from_env() -> UsedTokenStore:
    backend = os.environ.get("TOKEN_STORE_BACKEND", "memory").lower()
    if backend == "sqlite":
        return SQLiteUsedTokenStore(os.environ.get("TOKEN_STORE_SQLITE_PATH", "token_store.db"))
    return InMemoryUsedTokenStore()


def compute_payload_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_payload(token: GovernanceToken) -> str:
    payload = {
        "agent_id": token.agent_id,
        "expires_at": token.expires_at,
        "intent": token.intent,
        "issued_at": token.issued_at,
        "key_id": token.key_id,
        "nonce": token.nonce,
        "payload_hash": token.payload_hash,
        "policy_ids": list(token.policy_ids),
        "token_id": token.token_id,
        "tool_name": token.tool_name,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_token_payload(payload: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def build_token(
    *,
    key_id: str,
    agent_id: str,
    intent: str,
    tool_name: str,
    policy_ids: list[str],
    payload_hash: str,
    secret: str,
    ttl_seconds: int = 300,
    now: datetime | None = None,
) -> GovernanceToken:
    issued = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    expires = issued + timedelta(seconds=ttl_seconds)
    token = GovernanceToken(
        token_id=f"gtok_{uuid.uuid4().hex}",
        key_id=key_id,
        agent_id=agent_id,
        intent=intent,
        tool_name=tool_name,
        policy_ids=sorted(set(policy_ids)),
        payload_hash=payload_hash,
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
        key_id=str(data["key_id"]),
        agent_id=str(data["agent_id"]),
        intent=str(data["intent"]),
        tool_name=str(data["tool_name"]),
        policy_ids=[str(x) for x in data.get("policy_ids", [])],
        payload_hash=str(data["payload_hash"]),
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
    expected_key_id: str,
    expected_payload_hash: str,
    expected_intent: str | None = None,
    expected_policy_ids: list[str] | None = None,
) -> bool:
    now = datetime.now(timezone.utc)
    issued = _parse_iso8601(token.issued_at)
    expires = _parse_iso8601(token.expires_at)

    if issued > now or expires <= now:
        return False
    if token.key_id != expected_key_id:
        return False
    if token.agent_id != expected_agent_id:
        return False
    if token.tool_name != expected_tool_name:
        return False
    if token.payload_hash != expected_payload_hash:
        return False

    status = used_token_store.get_status(token.token_id)
    if status in {"pending", "consumed", "expired", "revoked"}:
        return False

    if expected_intent is not None and token.intent != expected_intent:
        return False
    if expected_policy_ids is not None and sorted(set(token.policy_ids)) != sorted(set(expected_policy_ids)):
        return False

    expected_sig = sign_token_payload(_canonical_payload(token), secret)
    return hmac.compare_digest(expected_sig, token.signature)
