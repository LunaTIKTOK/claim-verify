from __future__ import annotations

from typing import Any

from firewall import (
    AgentRuntime,
    ConstraintViolationError,
    Firewall,
    InMemoryFinalOutputSink,
    PreconditionRequiredError,
    QuarantineRequiredError,
)
from verify import VerificationResult


def toy_agent(context: dict[str, Any] | None = None) -> str:
    mode = (context or {}).get("mode", "allow")
    return f"proposal:{mode}"


def scripted_verifier(proposed_output: Any, context: dict[str, Any] | None = None) -> VerificationResult:
    mode = (context or {}).get("mode", "allow")
    base_report = {
        "token_waste_risk": "medium",
        "cost_estimate": {"expected_total_cost_usd": 0.12, "expected_compute_cost_usd": 0.12},
        "penalty_if_wrong": {"expected_loss": "medium", "cost_multiplier": 1.4},
        "aggregate_assumption_risk": "medium",
    }
    if mode == "allow":
        return VerificationResult(
            allowed=True,
            failed_constraints=[],
            warnings=[],
            report=base_report,
            decision="ALLOW",
            action_mode="execute_now",
            recommended_allocation=0.6,
            penalty_if_wrong=base_report["penalty_if_wrong"],
            aggregate_assumption_risk="medium",
            data_required=[],
            failure_cost_summary=[],
            cost_estimate=base_report["cost_estimate"],
            retry_tax_usd=0.0,
            quarantine_reason=None,
            audit_event={},
        )
    if mode == "fetch":
        return VerificationResult(
            allowed=False,
            failed_constraints=["FETCH_DATA_REQUIRED"],
            warnings=["TRUTH_STATUS_UNCERTAIN"],
            report={**base_report, "token_waste_risk": "high"},
            decision="FETCH_DATA_THEN_EXECUTE",
            action_mode="fetch_data_then_execute",
            recommended_allocation=0.1,
            penalty_if_wrong={"expected_loss": "high", "cost_multiplier": 2.5},
            aggregate_assumption_risk="high",
            data_required=["independent benchmark", "ground-truth source"],
            failure_cost_summary=["collect evidence before action"],
            cost_estimate=base_report["cost_estimate"],
            retry_tax_usd=1.9,
            quarantine_reason=None,
            audit_event={},
        )
    if mode == "bounded":
        return VerificationResult(
            allowed=True,
            failed_constraints=[],
            warnings=[],
            report=base_report,
            decision="EXECUTE_SMALL",
            action_mode="execute_small",
            recommended_allocation=0.25,
            penalty_if_wrong=base_report["penalty_if_wrong"],
            aggregate_assumption_risk="medium",
            data_required=["monitor key metric"],
            failure_cost_summary=["limit scope and checkpoint"],
            cost_estimate=base_report["cost_estimate"],
            retry_tax_usd=0.4,
            quarantine_reason=None,
            audit_event={},
        )
    if mode == "quarantine":
        return VerificationResult(
            allowed=False,
            failed_constraints=["SENSITIVE_PROMPT_DISCLOSURE"],
            warnings=[],
            report={**base_report, "token_waste_risk": "very_high"},
            decision="QUARANTINE",
            action_mode="consult_human",
            recommended_allocation=0.0,
            penalty_if_wrong={"expected_loss": "high", "cost_multiplier": 4.2},
            aggregate_assumption_risk="critical",
            data_required=["human review required"],
            failure_cost_summary=["quarantine until policy clearance"],
            cost_estimate=base_report["cost_estimate"],
            retry_tax_usd=3.2,
            quarantine_reason="Repeated unsafe disclosure pattern",
            audit_event={},
        )
    return VerificationResult(allowed=True, failed_constraints=[], warnings=[], report=base_report)


def build_runtime() -> AgentRuntime:
    sink = InMemoryFinalOutputSink(emitted=[])
    firewall = Firewall(sink=sink, verifier=scripted_verifier, strict_mode=False)
    return AgentRuntime(agent=toy_agent, firewall=firewall, max_violations=3)


def main() -> int:
    runtime = build_runtime()

    print("ALLOW:", runtime.run({"mode": "allow"}))

    try:
        runtime.run({"mode": "fetch"})
    except PreconditionRequiredError as exc:
        print("FETCH_DATA_THEN_EXECUTE:", exc.execution_plan)

    bounded = runtime.run({"mode": "bounded", "allow_bounded_execution": True, "max_allocation": 0.2})
    print("EXECUTE_SMALL_BOUNDED:", bounded)

    try:
        runtime.run({"mode": "quarantine"})
    except QuarantineRequiredError as exc:
        print("QUARANTINE:", exc.error_code, exc.retry_tax_usd, exc.quarantine_reason)

    for _ in range(2):
        try:
            runtime.run({"mode": "fetch"})
        except PreconditionRequiredError:
            pass
    print("RETRY_TAX_MEMORY:", runtime.session_state.cumulative_retry_tax_usd)
    print("ECONOMIC_SUMMARY:", runtime.economic_summary())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
