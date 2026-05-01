from __future__ import annotations

from dataclasses import asdict, dataclass


class AssumptionStatus:
    VERIFIED = "VERIFIED"
    OBSERVABLE = "OBSERVABLE"
    SPECULATIVE = "SPECULATIVE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass
class Assumption:
    assumption: str
    status: str
    confidence: float
    evidence: list[str]
    falsification_trigger: str | None
    critical: bool


@dataclass
class AssumptionMap:
    claim: str
    assumptions: list[Assumption]
    mode: str
    confidence_average: float
    max_allocation_pct: float
    falsification_triggers: list[str]


def _has_contradiction(evidence: list[str]) -> bool:
    lowered = [item.lower() for item in evidence]
    return any("contradict" in item or "refute" in item for item in lowered)


def evaluate_uncertainty(assumption_map: AssumptionMap) -> dict:
    for assumption in assumption_map.assumptions:
        if assumption.critical and assumption.status == AssumptionStatus.UNSUPPORTED:
            return {
                "decision": "BLOCK",
                "confidence_average": assumption_map.confidence_average,
                "max_allocation_pct": 0.0,
                "reason": "UNSUPPORTED_CRITICAL_ASSUMPTION",
                "falsification_triggers": assumption_map.falsification_triggers,
                "assumption_map": asdict(assumption_map),
            }
        if _has_contradiction(assumption.evidence):
            return {
                "decision": "BLOCK",
                "confidence_average": assumption_map.confidence_average,
                "max_allocation_pct": 0.0,
                "reason": "EVIDENCE_CONTRADICTION",
                "falsification_triggers": assumption_map.falsification_triggers,
                "assumption_map": asdict(assumption_map),
            }

    confidence = assumption_map.confidence_average
    if confidence < 0.45:
        return {
            "decision": "BLOCK",
            "confidence_average": confidence,
            "max_allocation_pct": 0.0,
            "reason": "LOW_CONFIDENCE",
            "falsification_triggers": assumption_map.falsification_triggers,
            "assumption_map": asdict(assumption_map),
        }

    if confidence < 0.75:
        cap = 2.0
        if confidence < 0.5:
            cap = 0.5
        elif confidence < 0.6:
            cap = 1.0
        return {
            "decision": "SPECULATE",
            "confidence_average": confidence,
            "max_allocation_pct": cap,
            "reason": None,
            "falsification_triggers": assumption_map.falsification_triggers,
            "assumption_map": asdict(assumption_map),
        }

    critical_ok = all(
        (not assumption.critical)
        or assumption.status in (AssumptionStatus.VERIFIED, AssumptionStatus.OBSERVABLE)
        for assumption in assumption_map.assumptions
    )
    if critical_ok:
        return {
            "decision": "ALLOW",
            "confidence_average": confidence,
            "max_allocation_pct": assumption_map.max_allocation_pct,
            "reason": None,
            "falsification_triggers": assumption_map.falsification_triggers,
            "assumption_map": asdict(assumption_map),
        }

    return {
        "decision": "SPECULATE",
        "confidence_average": confidence,
        "max_allocation_pct": 2.0,
        "reason": None,
        "falsification_triggers": assumption_map.falsification_triggers,
        "assumption_map": asdict(assumption_map),
    }
