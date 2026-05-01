from __future__ import annotations

import random
from dataclasses import asdict, dataclass


@dataclass
class ScenarioAssumption:
    name: str
    low: float
    base: float
    high: float
    weight: float
    critical: bool


@dataclass
class SimulationResult:
    simulation_count: int
    thesis_survival_rate: float
    sensitivity: str
    fragile_assumptions: list[str]
    decision: str
    max_allocation_pct: float
    falsification_triggers: list[str]
    reason: str | None


def run_scenario_simulation(
    claim: str,
    assumptions: list[ScenarioAssumption],
    simulation_count: int = 1000,
    seed: int = 42,
) -> dict:
    rng = random.Random(seed)
    total_weight = sum(max(assumption.weight, 0.0) for assumption in assumptions) or 1.0
    threshold = 0.6
    survive = 0
    critical_low_impact: dict[str, int] = {assumption.name: 0 for assumption in assumptions if assumption.critical}

    for _ in range(simulation_count):
        score = 0.0
        sampled: dict[str, float] = {}
        for assumption in assumptions:
            value = rng.triangular(assumption.low, assumption.high, assumption.base)
            sampled[assumption.name] = value
            score += value * assumption.weight
        normalized = score / total_weight
        survived = normalized >= threshold
        if survived:
            survive += 1
        for assumption in assumptions:
            if not assumption.critical:
                continue
            modified_score = score - (sampled[assumption.name] * assumption.weight) + (assumption.low * assumption.weight)
            if survived and (modified_score / total_weight) < threshold:
                critical_low_impact[assumption.name] += 1

    survival_rate = survive / max(simulation_count, 1)
    fragile = [name for name, hits in critical_low_impact.items() if hits > (survive * 0.6 if survive else 0)]
    if fragile:
        sensitivity = "HIGH"
    elif len(assumptions) > 1 and 0.45 <= survival_rate < 0.85:
        sensitivity = "MEDIUM"
    else:
        sensitivity = "LOW"

    if survival_rate < 0.45:
        decision = "BLOCK"
        cap = 0.0
        reason = "LOW_SIMULATION_SURVIVAL"
    elif survival_rate < 0.65:
        decision = "SPECULATE"
        cap = 0.5
        reason = None
    elif survival_rate < 0.80:
        decision = "SPECULATE"
        cap = 1.0
        reason = None
    else:
        decision = "SPECULATE"
        cap = 2.0
        reason = None

    result = SimulationResult(
        simulation_count=simulation_count,
        thesis_survival_rate=round(survival_rate, 6),
        sensitivity=sensitivity,
        fragile_assumptions=fragile,
        decision=decision,
        max_allocation_pct=cap,
        falsification_triggers=[f"{assumption.name} drops below base trend" for assumption in assumptions if assumption.critical],
        reason=reason,
    )
    return {"claim": claim, **asdict(result)}
