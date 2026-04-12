from __future__ import annotations

from typing import Any


def decide_policy(*, verification: dict[str, Any], toxic: dict[str, Any], identity_ok: bool, reputation_tier: str) -> str:
    if not identity_ok:
        return 'REQUIRE_REAUTH'
    if verification.get('structural_validity') == 'invalid':
        return 'DENY'
    if reputation_tier == 'QUARANTINED':
        return 'DENY'
    if toxic.get('quarantine_threshold_signal'):
        return 'ALLOW_WITH_CONSTRAINTS'
    if float(toxic.get('toxic_token_multiplier', 1.0)) >= 3.5:
        return 'DENY'
    if verification.get('confidence', 0.0) < 0.35:
        return 'DENY'
    if verification.get('fallback_used') or verification.get('reasoning_risk') in {'high', 'critical'}:
        return 'ALLOW_WITH_CONSTRAINTS'
    if toxic.get('required_constraints'):
        return 'ALLOW_WITH_CONSTRAINTS'
    return 'ALLOW'
