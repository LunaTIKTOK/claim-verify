from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

REQUIRED_FIELDS = (
    'agent_id','tenant_id','session_id','tool_id','action_name','model_id','runtime_id','key_id',
    'delegated_scope','policy_version','issued_at','expires_at','nonce','jti','payload_hash'
)


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def payload_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes({'payload': payload})).hexdigest()


@dataclass(frozen=True)
class IdentityEnvelope:
    agent_id: str
    tenant_id: str
    session_id: str
    tool_id: str
    action_name: str
    model_id: str
    runtime_id: str
    key_id: str
    delegated_scope: str
    policy_version: str
    issued_at: str
    expires_at: str
    nonce: str
    jti: str
    payload_hash: str

    def to_dict(self) -> dict[str, str]:
        return {
            'agent_id': self.agent_id,
            'tenant_id': self.tenant_id,
            'session_id': self.session_id,
            'tool_id': self.tool_id,
            'action_name': self.action_name,
            'model_id': self.model_id,
            'runtime_id': self.runtime_id,
            'key_id': self.key_id,
            'delegated_scope': self.delegated_scope,
            'policy_version': self.policy_version,
            'issued_at': self.issued_at,
            'expires_at': self.expires_at,
            'nonce': self.nonce,
            'jti': self.jti,
            'payload_hash': self.payload_hash,
        }


class IdentityValidationError(ValueError):
    pass


def _parse_time(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace('Z', '+00:00'))


def build_identity_envelope(*, action_name: str, payload: Any, context: dict[str, Any], policy_version: str, key_id: str) -> IdentityEnvelope:
    issued = str(context.get('issued_at') or _iso_utc_now())
    expires = str(context.get('expires_at') or issued)
    nonce = str(context.get('nonce') or '')
    jti = str(context.get('jti') or nonce)
    envelope = IdentityEnvelope(
        agent_id=str(context.get('agent_id', '')),
        tenant_id=str(context.get('tenant_id', '')),
        session_id=str(context.get('session_id', '')),
        tool_id=str(context.get('tool_id', '')),
        action_name=action_name,
        model_id=str(context.get('model_id', '')),
        runtime_id=str(context.get('runtime_id', '')),
        key_id=key_id,
        delegated_scope=str(context.get('delegated_scope', '')),
        policy_version=policy_version,
        issued_at=issued,
        expires_at=expires,
        nonce=nonce,
        jti=jti,
        payload_hash=payload_hash(payload),
    )
    validate_identity_envelope(envelope)
    return envelope


def validate_identity_envelope(envelope: IdentityEnvelope) -> None:
    data = envelope.to_dict()
    missing = [k for k in REQUIRED_FIELDS if not str(data.get(k, '')).strip()]
    if missing:
        raise IdentityValidationError(f'missing required identity fields: {", ".join(missing)}')
    try:
        issued = _parse_time(envelope.issued_at)
        expires = _parse_time(envelope.expires_at)
    except ValueError as exc:
        raise IdentityValidationError('issued_at/expires_at must be valid ISO-8601 timestamps') from exc
    if issued.tzinfo is None or expires.tzinfo is None:
        raise IdentityValidationError('issued_at/expires_at must include timezone information')
    if expires < issued:
        raise IdentityValidationError('expires_at must be greater than or equal to issued_at')
