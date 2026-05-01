from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from identity import IdentityEnvelope, canonical_json_bytes, payload_hash
from kms_provider import KMSProvider

ALLOWED_DECISIONS = {'ALLOW', 'ALLOW_WITH_CONSTRAINTS', 'DENY', 'REQUIRE_REAUTH'}
EXECUTABLE_DECISIONS = {'ALLOW', 'ALLOW_WITH_CONSTRAINTS'}


@dataclass(frozen=True)
class CapabilityReceipt:
    agent_id: str
    tenant_id: str
    session_id: str
    action_name: str
    payload_hash: str
    decision: str
    policy_version: str
    key_id: str
    issued_at: str
    expires_at: str
    jti: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return {
            'agent_id': self.agent_id,
            'tenant_id': self.tenant_id,
            'session_id': self.session_id,
            'action_name': self.action_name,
            'payload_hash': self.payload_hash,
            'decision': self.decision,
            'policy_version': self.policy_version,
            'key_id': self.key_id,
            'issued_at': self.issued_at,
            'expires_at': self.expires_at,
            'jti': self.jti,
            'signature': self.signature,
        }


def _unsigned_receipt_dict(envelope: IdentityEnvelope, *, decision: str) -> dict[str, str]:
    return {
        'agent_id': envelope.agent_id,
        'tenant_id': envelope.tenant_id,
        'session_id': envelope.session_id,
        'action_name': envelope.action_name,
        'payload_hash': envelope.payload_hash,
        'decision': decision,
        'policy_version': envelope.policy_version,
        'key_id': envelope.key_id,
        'issued_at': envelope.issued_at,
        'expires_at': envelope.expires_at,
        'jti': envelope.jti,
    }


def issue_receipt(envelope: IdentityEnvelope, *, decision: str, provider: KMSProvider) -> CapabilityReceipt:
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(f'unsupported receipt decision: {decision}')
    data = _unsigned_receipt_dict(envelope, decision=decision)
    signature = provider.sign(canonical_json_bytes(data))
    return CapabilityReceipt(signature=signature, **data)


def _parse_time(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace('Z', '+00:00'))


def validate_receipt(receipt: CapabilityReceipt, *, action_name: str, payload: Any, provider: KMSProvider, now: datetime | None = None) -> tuple[bool, str]:
    if receipt.action_name != action_name:
        return False, 'ACTION_MISMATCH'
    if receipt.payload_hash != payload_hash(payload):
        return False, 'PAYLOAD_MISMATCH'
    if receipt.key_id != provider.key_id():
        return False, 'INVALID_KEY'
    if receipt.decision not in ALLOWED_DECISIONS:
        return False, 'INVALID_DECISION'
    if receipt.decision not in EXECUTABLE_DECISIONS:
        return False, 'INVALID_DECISION'
    unsigned = receipt.to_dict().copy()
    signature = unsigned.pop('signature')
    if not provider.verify(canonical_json_bytes(unsigned), signature):
        return False, 'INVALID_SIGNATURE'
    current = now or datetime.now(timezone.utc)
    if _parse_time(receipt.issued_at) > current:
        return False, 'RECEIPT_NOT_YET_VALID'
    if _parse_time(receipt.expires_at) < current:
        return False, 'EXPIRED_RECEIPT'
    if _parse_time(receipt.expires_at) < _parse_time(receipt.issued_at):
        return False, 'INVALID_TIME_WINDOW'
    return True, 'OK'
