from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from firewall import (
    AgentRuntime,
    ConstraintViolationError,
    Firewall,
    InMemoryFinalOutputSink,
    PreconditionRequiredError,
    QuarantineRequiredError,
    SessionResetError,
)
from verify import VerificationResult


@dataclass
class ScenarioConfig:
    name: str
    mode: str
    attempts: int
    allow_bounded_execution: bool = False
    max_allocation: float | None = None


def scenario_verifier(_proposed_output: Any, context: dict[str, Any] | None = None) -> VerificationResult:
    mode = str((context or {}).get("mode", "compliant"))
    violation_count = int((context or {}).get("violation_count", 0))
    base_cost = {"expected_total_cost_usd": 0.08, "expected_compute_cost_usd": 0.08}

    if mode == "compliant":
        return VerificationResult(
            allowed=True,
            failed_constraints=[],
            warnings=[],
            report={"token_waste_risk": "low", "expected_value": 0.3},
            decision="ALLOW",
            action_mode="execute_now",
            recommended_allocation=0.55,
            penalty_if_wrong={"expected_loss": "low", "expected_failure_cost_usd": 0.05},
            aggregate_assumption_risk="low",
            cost_estimate=base_cost,
            retry_tax_usd=0.0,
        )

    if mode == "ambiguous":
        return VerificationResult(
            allowed=False,
            failed_constraints=["FETCH_DATA_REQUIRED"],
            warnings=["TRUTH_STATUS_UNCERTAIN"],
            report={"token_waste_risk": "high", "expected_value": 0.05},
            decision="FETCH_DATA_THEN_EXECUTE",
            action_mode="fetch_data_then_execute",
            recommended_allocation=0.1,
            penalty_if_wrong={"expected_loss": "medium", "expected_failure_cost_usd": 0.25},
            aggregate_assumption_risk="high",
            data_required=["ground truth", "baseline benchmark"],
            failure_cost_summary=["collect data before release"],
            cost_estimate={"expected_total_cost_usd": 0.16, "expected_compute_cost_usd": 0.16},
            retry_tax_usd=1.2,
        )

    if mode == "sloppy":
        retry_tax = min(4.5, 0.8 + (violation_count * 0.7))
        return VerificationResult(
            allowed=False,
            failed_constraints=["LOGIC_INSUFFICIENT_SUPPORT"],
            warnings=["TRUTH_STATUS_UNCERTAIN"],
            report={"token_waste_risk": "very_high", "expected_value": -0.1},
            decision="CONSULT_HUMAN",
            action_mode="consult_human",
            recommended_allocation=0.0,
            penalty_if_wrong={"expected_loss": "high", "expected_failure_cost_usd": 0.8},
            aggregate_assumption_risk="high",
            cost_estimate={"expected_total_cost_usd": 0.22, "expected_compute_cost_usd": 0.22},
            retry_tax_usd=retry_tax,
        )

    return VerificationResult(
        allowed=False,
        failed_constraints=["SENSITIVE_PROMPT_DISCLOSURE"],
        warnings=[],
        report={"token_waste_risk": "very_high", "expected_value": -0.5},
        decision="QUARANTINE",
        action_mode="consult_human",
        recommended_allocation=0.0,
        penalty_if_wrong={"expected_loss": "high", "expected_failure_cost_usd": 1.4},
        aggregate_assumption_risk="critical",
        cost_estimate={"expected_total_cost_usd": 0.35, "expected_compute_cost_usd": 0.35},
        retry_tax_usd=3.6,
        quarantine_reason="high-risk unsafe disclosure profile",
    )


def toy_agent(context: dict[str, Any] | None = None) -> str:
    return f"draft:{(context or {}).get('mode', 'compliant')}"


def run_firewall_scenario(config: ScenarioConfig) -> dict[str, Any]:
    sink = InMemoryFinalOutputSink(emitted=[])
    firewall = Firewall(sink=sink, verifier=scenario_verifier, audit_path=None)
    runtime = AgentRuntime(agent=toy_agent, firewall=firewall)

    start = time.perf_counter()
    attempts = 0
    decision_distribution: dict[str, int] = {}
    released = False
    terminal_stop = False
    cumulative_retry_tax_usd = 0.0

    for _ in range(config.attempts):
        attempts += 1
        ctx = {"mode": config.mode}
        if config.allow_bounded_execution:
            ctx["allow_bounded_execution"] = True
        if config.max_allocation is not None:
            ctx["max_allocation"] = config.max_allocation
        try:
            out = runtime.run(ctx)
            released = True
            if isinstance(out, dict) and "decision" in out:
                decision_distribution[out["decision"]] = decision_distribution.get(out["decision"], 0) + 1
            else:
                decision_distribution[ctx.get("decision", "ALLOW")] = decision_distribution.get(ctx.get("decision", "ALLOW"), 0) + 1
            break
        except PreconditionRequiredError as exc:
            decision_distribution["FETCH_DATA_THEN_EXECUTE"] = decision_distribution.get("FETCH_DATA_THEN_EXECUTE", 0) + 1
            # execution_plan always includes retry_tax_usd
            # pyright: ignore[reportAttributeAccessIssue]
            cumulative_retry_tax_usd += float(getattr(exc, "execution_plan", {}).get("retry_tax_usd", 0.0))
        except QuarantineRequiredError as exc:
            decision_distribution["QUARANTINE"] = decision_distribution.get("QUARANTINE", 0) + 1
            cumulative_retry_tax_usd += float(exc.retry_tax_usd)
            terminal_stop = True
            break
        except ConstraintViolationError as exc:
            decision_distribution[exc.error_code] = decision_distribution.get(exc.error_code, 0) + 1
            cumulative_retry_tax_usd += float((exc.verification_report or {}).get("retry_tax_usd", 0.0))
        except SessionResetError:
            decision_distribution["SESSION_RESET"] = decision_distribution.get("SESSION_RESET", 0) + 1
            terminal_stop = True
            break

    elapsed = round(time.perf_counter() - start, 6)
    estimated_compute_cost = round(attempts * 0.12, 6)
    estimated_failure_cost_avoided = round(cumulative_retry_tax_usd * 0.7, 6)
    return {
        "scenario": config.name,
        "attempts": attempts,
        "cumulative_retry_tax_usd": round(cumulative_retry_tax_usd, 6),
        "estimated_compute_cost_usd": estimated_compute_cost,
        "estimated_failure_cost_avoided_usd": estimated_failure_cost_avoided,
        "final_decision_distribution": decision_distribution,
        "output_released": released,
        "terminal_stop": terminal_stop,
        "time_to_success_or_stop_sec": elapsed,
    }


def run_naive_scenario(config: ScenarioConfig) -> dict[str, Any]:
    attempts = config.attempts
    blocked_bad_releases = 0
    quarantine_count = 0
    bounded_releases = 0
    if config.mode in {"sloppy", "quarantine"}:
        blocked_bad_releases = 0
    if config.mode == "quarantine":
        quarantine_count = 0
    if config.mode == "ambiguous":
        bounded_releases = 0
    compute_cost = round(attempts * 0.2, 6)
    retry_cost = round(attempts * 0.05, 6)
    return {
        "scenario": config.name,
        "total_compute_cost_usd": compute_cost,
        "total_retry_cost_usd": retry_cost,
        "expected_failure_cost_usd": 0.8 if config.mode in {"sloppy", "quarantine"} else 0.15,
        "blocked_bad_releases": blocked_bad_releases,
        "bounded_releases": bounded_releases,
        "quarantine_count": quarantine_count,
    }


def benchmark() -> dict[str, Any]:
    scenarios = [
        ScenarioConfig(name="compliant_low_risk_agent", mode="compliant", attempts=1),
        ScenarioConfig(name="ambiguous_unsupported_agent", mode="ambiguous", attempts=2),
        ScenarioConfig(name="repeated_violation_sloppy_agent", mode="sloppy", attempts=4),
        ScenarioConfig(name="high_risk_quarantine_agent", mode="quarantine", attempts=2),
    ]

    firewall_results = [run_firewall_scenario(s) for s in scenarios]
    naive_results = [run_naive_scenario(s) for s in scenarios]

    firewall_totals = {
        "total_compute_cost_usd": round(sum(item["estimated_compute_cost_usd"] for item in firewall_results), 6),
        "total_retry_cost_usd": round(sum(item["cumulative_retry_tax_usd"] for item in firewall_results), 6),
        "blocked_bad_releases": sum(1 for item in firewall_results if not item["output_released"]),
        "bounded_releases": sum(1 for item in firewall_results if "EXECUTE_SMALL" in item["final_decision_distribution"]),
        "quarantine_count": sum(item["final_decision_distribution"].get("QUARANTINE", 0) for item in firewall_results),
    }
    naive_totals = {
        "total_compute_cost_usd": round(sum(item["total_compute_cost_usd"] for item in naive_results), 6),
        "total_retry_cost_usd": round(sum(item["total_retry_cost_usd"] for item in naive_results), 6),
        "expected_failure_cost_usd": round(sum(item["expected_failure_cost_usd"] for item in naive_results), 6),
        "blocked_bad_releases": sum(item["blocked_bad_releases"] for item in naive_results),
        "bounded_releases": sum(item["bounded_releases"] for item in naive_results),
        "quarantine_count": sum(item["quarantine_count"] for item in naive_results),
    }
    firewall_failure_cost_avoided = round(sum(item["estimated_failure_cost_avoided_usd"] for item in firewall_results), 6)
    naive_total_burden = naive_totals["total_compute_cost_usd"] + naive_totals["total_retry_cost_usd"] + naive_totals["expected_failure_cost_usd"]
    firewall_total_burden = firewall_totals["total_compute_cost_usd"] + firewall_totals["total_retry_cost_usd"]

    return {
        "scenarios": firewall_results,
        "comparison": {
            "naive_direct_execution": naive_totals,
            "firewall_execution": firewall_totals,
            "estimated_cost_saved_by_firewall_usage_usd": round((naive_total_burden - firewall_total_burden) + firewall_failure_cost_avoided, 6),
        },
    }


if __name__ == "__main__":
    print(json.dumps(benchmark(), indent=2))
