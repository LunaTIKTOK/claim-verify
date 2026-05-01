from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ReputationRecord:
    fallback_count: int = 0
    denial_count: int = 0
    retry_count: int = 0
    invalid_signature_attempts: int = 0
    warning_code_frequency: dict[str, int] = field(default_factory=dict)
    confidence_drift: float = 0.0
    degraded_execution_count: int = 0
    total_events: int = 0

    def fallback_rate(self) -> float:
        return self.fallback_count / max(1, self.total_events)

    def denial_rate(self) -> float:
        return self.denial_count / max(1, self.total_events)


def update_reputation(record: ReputationRecord, *, warning_codes: list[str], fallback_used: bool, denied: bool, retried: bool, invalid_signature: bool, confidence: float, degraded: bool) -> ReputationRecord:
    record.total_events += 1
    if fallback_used:
        record.fallback_count += 1
    if denied:
        record.denial_count += 1
    if retried:
        record.retry_count += 1
    if invalid_signature:
        record.invalid_signature_attempts += 1
    if degraded:
        record.degraded_execution_count += 1
    for code in warning_codes:
        record.warning_code_frequency[code] = record.warning_code_frequency.get(code, 0) + 1
    record.confidence_drift += max(0.0, 0.7 - confidence)
    return record


def reputation_tier(record: ReputationRecord) -> str:
    if record.invalid_signature_attempts >= 3 or record.denial_rate() >= 0.6:
        return 'QUARANTINED'
    if record.invalid_signature_attempts >= 1:
        return 'HIGH_RISK'
    if record.denial_rate() >= 0.4 or record.fallback_rate() >= 0.4:
        return 'HIGH_RISK'
    if record.denial_rate() >= 0.2 or record.fallback_rate() >= 0.2:
        return 'CONSTRAINED'
    return 'TRUSTED'
