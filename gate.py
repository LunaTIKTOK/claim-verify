from __future__ import annotations

from typing import Any, Callable

from audit import AuditLogger
from identity import IdentityValidationError, build_identity_envelope, validate_identity_envelope
from kms_provider import KMSProvider
from policy import decide_policy
from receipt import issue_receipt, validate_receipt
from reputation import ReputationRecord, reputation_tier, update_reputation
from toxic_cost import price_toxic_tokens
from verify import evaluate_input


def submit_action(action_name: str, payload: Any, context: dict[str, Any], executor: Callable[[Any, Any], Any], *, provider: KMSProvider, policy_version: str = 'dev', audit_logger: AuditLogger | None = None, reputation_record: ReputationRecord | None = None) -> dict[str, Any]:
    record = reputation_record or ReputationRecord()
    try:
        envelope = build_identity_envelope(
            action_name=action_name,
            payload=payload,
            context=context,
            policy_version=policy_version,
            key_id=provider.key_id(),
        )
        validate_identity_envelope(envelope)
    except IdentityValidationError as exc:
        if audit_logger:
            audit_logger.log('POLICY_REAUTH', {'action_name': action_name, 'reason': str(exc)})
        return {'decision': 'REQUIRE_REAUTH', 'reason': 'INVALID_IDENTITY', 'executed': False}

    claim_text = str(payload.get('claim', action_name)) if isinstance(payload, dict) else str(payload)
    verification = evaluate_input(claim_text)
    warning_codes = list(verification.get('claim_graph_warnings') or [])
    fallback_used = bool(warning_codes)

    tier = reputation_tier(record)
    toxic = price_toxic_tokens(
        warning_codes=warning_codes,
        fallback_used=fallback_used,
        denial_history=record.denial_count,
        confidence=float(verification.get('confidence', 0.0)),
        evidence_strength=str(verification.get('evidence_strength', 'none')),
        claim_graph_invalidity=fallback_used,
        retry_count=record.retry_count,
        reputation_tier=tier,
    )

    verification_view = {
        'structural_validity': verification.get('structural_validity'),
        'confidence': verification.get('confidence', 0.0),
        'reasoning_risk': verification.get('reasoning_contamination_risk', 'medium'),
        'fallback_used': fallback_used,
    }
    decision = decide_policy(
        verification=verification_view,
        toxic=toxic,
        identity_ok=True,
        reputation_tier=tier,
    )

    if decision in {'DENY', 'REQUIRE_REAUTH'}:
        update_reputation(
            record,
            warning_codes=warning_codes,
            fallback_used=fallback_used,
            denied=True,
            retried=bool(context.get('retry_count', 0)),
            invalid_signature=False,
            confidence=float(verification.get('confidence', 0.0)),
            degraded=True,
        )
        if audit_logger:
            audit_logger.log('DENY', {'decision': decision, 'agent_id': envelope.agent_id, 'action_name': action_name})
            if decision == 'REQUIRE_REAUTH':
                audit_logger.log('POLICY_REAUTH', {'agent_id': envelope.agent_id, 'action_name': action_name})
            if fallback_used:
                audit_logger.log('FALLBACK_USED', {'agent_id': envelope.agent_id, 'warnings': warning_codes})
            if float(verification.get('confidence', 0.0)) < 0.5:
                audit_logger.log('DEGRADED_REASONING', {'agent_id': envelope.agent_id})
        return {
            'decision': decision,
            'verification': verification,
            'toxic_cost': toxic,
            'constraints': list(toxic.get('required_constraints') or []),
            'executed': False,
        }

    receipt = issue_receipt(envelope, decision=decision, provider=provider)
    ok, code = validate_receipt(receipt, action_name=action_name, payload=payload, provider=provider)
    if not ok:
        update_reputation(
            record,
            warning_codes=warning_codes,
            fallback_used=fallback_used,
            denied=True,
            retried=bool(context.get('retry_count', 0)),
            invalid_signature=code == 'INVALID_SIGNATURE',
            confidence=float(verification.get('confidence', 0.0)),
            degraded=True,
        )
        if audit_logger:
            audit_logger.log(code, {'agent_id': envelope.agent_id, 'action_name': action_name})
        return {
            'decision': 'DENY',
            'reason': code,
            'verification': verification,
            'toxic_cost': toxic,
            'constraints': list(toxic.get('required_constraints') or []),
            'executed': False,
        }

    result = executor(receipt, payload)
    update_reputation(
        record,
        warning_codes=warning_codes,
        fallback_used=fallback_used,
        denied=False,
        retried=bool(context.get('retry_count', 0)),
        invalid_signature=False,
        confidence=float(verification.get('confidence', 0.0)),
        degraded=decision == 'ALLOW_WITH_CONSTRAINTS',
    )
    if audit_logger:
        audit_logger.log('ALLOW', {'decision': decision, 'agent_id': envelope.agent_id, 'action_name': action_name})
        if fallback_used:
            audit_logger.log('FALLBACK_USED', {'agent_id': envelope.agent_id, 'warnings': warning_codes})
        if decision == 'ALLOW_WITH_CONSTRAINTS':
            audit_logger.log('DEGRADED_REASONING', {'agent_id': envelope.agent_id})
        if record.denial_count >= 3:
            audit_logger.log('REPEATED_DENIALS', {'agent_id': envelope.agent_id, 'denials': record.denial_count})

    return {
        'decision': decision,
        'verification': verification,
        'toxic_cost': toxic,
        'constraints': list(toxic.get('required_constraints') or []),
        'receipt': receipt.to_dict(),
        'result': result,
        'executed': True,
    }
