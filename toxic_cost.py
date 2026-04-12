from __future__ import annotations

from typing import Any


def price_toxic_tokens(*, warning_codes: list[str], fallback_used: bool, denial_history: int, confidence: float, evidence_strength: str, claim_graph_invalidity: bool, retry_count: int, reputation_tier: str) -> dict[str, Any]:
    confidence = min(1.0, max(0.0, confidence))
    multiplier = 1.0
    multiplier += 0.15 * len(warning_codes)
    if fallback_used:
        multiplier += 0.25
    multiplier += min(denial_history, 5) * 0.1
    multiplier += max(0.0, 0.7 - confidence)
    if evidence_strength in {'none', 'weak'}:
        multiplier += 0.25
    if claim_graph_invalidity:
        multiplier += 0.3
    multiplier += min(retry_count, 5) * 0.1
    if reputation_tier in {'HIGH_RISK', 'QUARANTINED'}:
        multiplier += 0.5

    required_constraints: list[str] = []
    if multiplier >= 1.5:
        required_constraints.append('rate_limit_strict')
    if multiplier >= 2.0:
        required_constraints.append('read_only_tools')

    return {
        'toxic_token_multiplier': round(multiplier, 3),
        'required_constraints': required_constraints,
        'recommended_latency_penalty': min(5, int(multiplier)),
        'quarantine_threshold_signal': multiplier >= 2.5,
    }
