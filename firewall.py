from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from verify import VerificationResult, verify_output


class ConstraintViolationError(Exception):
    """Raised when cognitive firewall verification blocks an output proposal."""

    def __init__(
        self,
        message: str,
        *,
        failed_constraints: list[str],
        error_code: str,
        verification_report: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.failed_constraints = failed_constraints
        self.error_code = error_code
        self.verification_report = verification_report


class SessionResetError(Exception):
    """Raised when repeated constraint violations force a hard session reset."""

    def __init__(self, message: str, *, threshold: int) -> None:
        super().__init__(message)
        self.threshold = threshold


class QuarantineRequiredError(Exception):
    """Raised when policy requires quarantining agent output."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        failed_constraints: list[str],
        verification_report: dict[str, Any] | None,
        penalty_if_wrong: dict[str, Any],
        retry_tax_usd: float,
        quarantine_reason: str | None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.failed_constraints = failed_constraints
        self.verification_report = verification_report
        self.penalty_if_wrong = penalty_if_wrong
        self.retry_tax_usd = retry_tax_usd
        self.quarantine_reason = quarantine_reason


class PreconditionRequiredError(Exception):
    """Raised when output cannot be released before prerequisite data collection."""

    def __init__(self, message: str, *, execution_plan: dict[str, Any]) -> None:
        super().__init__(message)
        self.execution_plan = execution_plan


class OutputVerifier(Protocol):
    def __call__(self, proposed_output: Any, context: dict[str, Any] | None = None) -> VerificationResult:
        ...


class OutputSink(Protocol):
    def send(self, output: Any) -> Any:
        ...


@dataclass
class InMemoryFinalOutputSink:
    """Simple sink implementation used by tests/examples."""

    emitted: list[Any]

    def send(self, output: Any) -> Any:
        self.emitted.append(output)
        return output


class Firewall:
    """Middleware-enforced cognitive firewall for final output release."""

    __slots__ = ("_verifier", "_strict_mode", "__sink", "_audit_path")

    def __init__(
        self,
        sink: OutputSink,
        *,
        verifier: OutputVerifier | None = None,
        strict_mode: bool = False,
        audit_path: str | None = "logs/firewall_audit.jsonl",
    ) -> None:
        self.__sink = sink
        self._verifier = verifier or verify_output
        self._strict_mode = strict_mode
        self._audit_path = Path(audit_path) if audit_path else None

    def _log_audit(self, result: VerificationResult, *, proposed_output: Any, released: bool, session_reset: bool = False) -> None:
        if self._audit_path is None:
            return
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proposed_output_hash": hashlib.sha256(str(proposed_output).encode("utf-8")).hexdigest(),
            "decision": result.decision,
            "failed_constraints": result.failed_constraints,
            "warnings": result.warnings,
            "aggregate_assumption_risk": result.aggregate_assumption_risk,
            "token_waste_risk": result.report.get("token_waste_risk"),
            "retry_tax_usd": result.retry_tax_usd,
            "estimated_total_cost_usd": result.cost_estimate.get("expected_total_cost_usd", result.cost_estimate.get("total_expected_cost_usd")),
            "output_released": released,
            "session_reset": session_reset,
        }
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    def submit_response(self, proposed_output: Any, context: dict[str, Any] | None = None) -> Any:
        result = self._verifier(proposed_output, context)
        decision = result.decision
        runtime_context = context or {}
        pressure_mode = str(runtime_context.get("budget_pressure_mode", "")).lower()
        if pressure_mode == "consult_human":
            decision = "CONSULT_HUMAN"
        elif pressure_mode == "fetch_data_first" and decision in {"ALLOW", "ALLOW_WITH_WARNING", "EXECUTE_SMALL", "EXECUTE_WITH_ASSUMPTIONS"}:
            decision = "FETCH_DATA_THEN_EXECUTE"
        elif pressure_mode == "bounded_only" and decision in {"ALLOW", "ALLOW_WITH_WARNING"}:
            decision = "EXECUTE_SMALL"
        if isinstance(context, dict):
            context["decision"] = decision
        if decision in {"HARD_STOP", "CONSULT_HUMAN"}:
            self._log_audit(result, proposed_output=proposed_output, released=False)
            raise ConstraintViolationError(
                "Output blocked by cognitive firewall constraints.",
                failed_constraints=result.failed_constraints,
                error_code=decision,
                verification_report={
                    **result.report,
                    "decision": decision,
                    "retry_tax_usd": result.retry_tax_usd,
                    "penalty_if_wrong": result.penalty_if_wrong,
                },
            )
        if decision == "QUARANTINE":
            self._log_audit(result, proposed_output=proposed_output, released=False)
            raise QuarantineRequiredError(
                "Output quarantined by cognitive firewall economics.",
                error_code="QUARANTINE_REQUIRED",
                failed_constraints=result.failed_constraints,
                verification_report=result.report,
                penalty_if_wrong=result.penalty_if_wrong,
                retry_tax_usd=result.retry_tax_usd,
                quarantine_reason=result.quarantine_reason,
            )
        if decision == "FETCH_DATA_THEN_EXECUTE":
            self._log_audit(result, proposed_output=proposed_output, released=False)
            raise PreconditionRequiredError(
                "Output blocked pending required data collection.",
                execution_plan={
                    "decision": decision,
                    "action_mode": result.action_mode,
                    "data_required": result.data_required,
                    "failure_cost_summary": result.failure_cost_summary,
                    "retry_tax_usd": result.retry_tax_usd,
                    "recommended_next_action": "collect_evidence_first",
                },
            )
        if decision in {"EXECUTE_SMALL", "EXECUTE_WITH_ASSUMPTIONS"}:
            runtime_context = context or {}
            if not bool(runtime_context.get("allow_bounded_execution", False)):
                self._log_audit(result, proposed_output=proposed_output, released=False)
                raise ConstraintViolationError(
                    "Bounded execution required but not enabled in context.",
                    failed_constraints=result.failed_constraints or [decision],
                    error_code="BOUNDED_EXECUTION_REQUIRED",
                    verification_report={**result.report, "decision": decision, "retry_tax_usd": result.retry_tax_usd},
                )
            max_allocation = runtime_context.get("max_allocation")
            allocation = result.recommended_allocation
            if max_allocation is not None:
                allocation = min(allocation, float(max_allocation))
            payload = {
                "released_output": self.__sink.send(proposed_output),
                "decision": decision,
                "allocation": allocation,
                "retry_tax_usd": result.retry_tax_usd,
                "penalty_if_wrong": result.penalty_if_wrong,
            }
            self._log_audit(result, proposed_output=proposed_output, released=True)
            return payload
        if self._strict_mode and result.warnings:
            self._log_audit(result, proposed_output=proposed_output, released=False)
            raise ConstraintViolationError(
                "Output blocked in strict mode due to verification warnings.",
                failed_constraints=result.warnings,
                error_code="WARNINGS_BLOCKED_IN_STRICT_MODE",
                verification_report=result.report,
            )
        released = self.__sink.send(proposed_output)
        self._log_audit(result, proposed_output=proposed_output, released=True)
        return released


class AgentRuntime:
    """Runtime boundary: agent can propose output, firewall controls release."""

    __slots__ = ("_agent", "_firewall", "_state", "_max_violations", "_budget_downgrade_threshold_usd", "_budget_consult_threshold_usd")

    def __init__(
        self,
        agent: Callable[[dict[str, Any] | None], Any],
        firewall: Firewall,
        *,
        max_violations: int = 3,
        budget_downgrade_threshold_usd: float = 5.0,
        budget_consult_threshold_usd: float = 10.0,
    ) -> None:
        self._agent = agent
        self._firewall = firewall
        self._state = SessionState()
        self._max_violations = max_violations
        self._budget_downgrade_threshold_usd = budget_downgrade_threshold_usd
        self._budget_consult_threshold_usd = budget_consult_threshold_usd

    @property
    def session_state(self) -> "SessionState":
        return self._state

    def _warning_severity(self) -> str:
        if self._state.violation_count >= max(1, self._max_violations - 1):
            return "FINAL WARNING"
        if self._state.violation_count >= 2:
            return "CRITICAL WARNING"
        return "WARNING"

    def _compose_warning_prefix(self) -> str:
        if self._state.violation_count <= 0:
            return ""
        failed = ", ".join(self._state.last_failed_constraints) or "UNKNOWN_CONSTRAINT"
        return (
            f"System Warning [{self._warning_severity()}]: "
            f"You have violated constraint(s): {failed}. "
            "Correct this immediately to avoid session reset."
        )

    def _reset_session(self) -> None:
        self._state.violation_count = 0
        self._state.last_failed_constraints = []
        self._state.cumulative_retry_tax_usd = 0.0
        self._state.last_penalty_if_wrong = None

    def run(self, context: dict[str, Any] | None = None) -> Any:
        runtime_context = dict(context or {})
        if self._state.cumulative_retry_tax_usd >= self._budget_consult_threshold_usd:
            runtime_context["budget_pressure_mode"] = "consult_human"
        elif self._state.cumulative_retry_tax_usd >= self._budget_downgrade_threshold_usd:
            runtime_context["budget_pressure_mode"] = "fetch_data_first"
            runtime_context["allow_bounded_execution"] = bool(runtime_context.get("allow_bounded_execution", False))
        warning_prefix = self._compose_warning_prefix()
        if warning_prefix:
            prior_prompt = str(runtime_context.get("prompt", ""))
            runtime_context["prompt"] = f"{warning_prefix}\n\n{prior_prompt}" if prior_prompt else warning_prefix
        runtime_context["violation_count"] = self._state.violation_count
        proposal = self._agent(runtime_context)
        try:
            released = self._firewall.submit_response(proposal, runtime_context)
            self._state.decision_history.append(str(runtime_context.get("decision", "ALLOW")))
            return released
        except ConstraintViolationError as exc:
            self._state.violation_count += 1
            self._state.last_failed_constraints = list(exc.failed_constraints)
            retry_tax_usd = float((exc.verification_report or {}).get("retry_tax_usd", 0.0))
            self._state.cumulative_retry_tax_usd += retry_tax_usd
            self._state.last_penalty_if_wrong = dict((exc.verification_report or {}).get("penalty_if_wrong") or {})
            self._state.decision_history.append(str((exc.verification_report or {}).get("decision", exc.error_code)))
            if self._state.violation_count > self._max_violations:
                self._reset_session()
                raise SessionResetError(
                    "Session hard-reset after repeated cognitive firewall violations.",
                    threshold=self._max_violations,
                ) from exc
            raise
        except QuarantineRequiredError as exc:
            self._state.violation_count += 1
            self._state.cumulative_retry_tax_usd += float(exc.retry_tax_usd)
            self._state.last_failed_constraints = list(exc.failed_constraints)
            self._state.last_penalty_if_wrong = dict(exc.penalty_if_wrong or {})
            self._state.decision_history.append("QUARANTINE")
            raise
        except PreconditionRequiredError as exc:
            plan = exc.execution_plan
            self._state.violation_count += 1
            self._state.cumulative_retry_tax_usd += float(plan.get("retry_tax_usd", 0.0))
            self._state.last_failed_constraints = [str(plan.get("decision", "FETCH_DATA_THEN_EXECUTE"))]
            self._state.last_penalty_if_wrong = {}
            self._state.decision_history.append("FETCH_DATA_THEN_EXECUTE")
            raise

    def economic_summary(self) -> dict[str, Any]:
        retry_tax_if_skipped = self._state.cumulative_retry_tax_usd
        expected_compute_saved = round(retry_tax_if_skipped * 0.35, 6)
        expected_error_cost_avoided = round(retry_tax_if_skipped * 0.65, 6)
        if self._state.last_failed_constraints:
            recommended_next_action = "address_failed_constraints_before_retry"
        else:
            recommended_next_action = "continue_guarded_execution"
        return {
            "expected_compute_saved": expected_compute_saved,
            "expected_error_cost_avoided": expected_error_cost_avoided,
            "retry_tax_if_skipped": round(retry_tax_if_skipped, 6),
            "recommended_next_action": recommended_next_action,
        }

    def economic_report(self) -> dict[str, Any]:
        retry_tax = round(self._state.cumulative_retry_tax_usd, 6)
        expected_compute_saved_usd = round(retry_tax * 0.35, 6)
        expected_failure_cost_avoided_usd = round(retry_tax * 0.65, 6)
        firewall_value_score = round(min(100.0, (expected_compute_saved_usd + expected_failure_cost_avoided_usd) * 10), 3)
        if self._state.cumulative_retry_tax_usd >= self._budget_consult_threshold_usd:
            recommended_next_action = "consult_human"
        elif self._state.cumulative_retry_tax_usd >= self._budget_downgrade_threshold_usd:
            recommended_next_action = "fetch_data_then_verify"
        else:
            recommended_next_action = "verify_then_execute"
        return {
            "expected_compute_saved_usd": expected_compute_saved_usd,
            "expected_failure_cost_avoided_usd": expected_failure_cost_avoided_usd,
            "cumulative_retry_tax_usd": retry_tax,
            "firewall_value_score": firewall_value_score,
            "recommended_next_action": recommended_next_action,
        }


@dataclass
class SessionState:
    violation_count: int = 0
    last_failed_constraints: list[str] = None  # type: ignore[assignment]
    cumulative_retry_tax_usd: float = 0.0
    decision_history: list[str] = None  # type: ignore[assignment]
    last_penalty_if_wrong: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.last_failed_constraints is None:
            self.last_failed_constraints = []
        if self.decision_history is None:
            self.decision_history = []
