from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from firewall import (
    ConstraintViolationError,
    Firewall,
    InMemoryFinalOutputSink,
    PreconditionRequiredError,
    QuarantineRequiredError,
)
from verify import verify_output


BLOCKING_DECISIONS = {"HARD_STOP", "QUARANTINE", "CONSULT_HUMAN"}
SECRET_SAFE_DECISIONS = {"ALLOW", "EXECUTE_SMALL"}


def _emit_output(name: str, value: str) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def main() -> int:
    proposed_output = os.environ.get(
        "FIREWALL_PROPOSED_OUTPUT",
        "System has measurable 99% uptime in 30 days.",
    )
    context: dict[str, Any] = {
        "expected_benefit": float(os.environ.get("FIREWALL_EXPECTED_BENEFIT", "10.0")),
        "benefit_confidence": float(os.environ.get("FIREWALL_BENEFIT_CONFIDENCE", "1.0")),
        "allow_bounded_execution": os.environ.get("FIREWALL_ALLOW_BOUNDED", "true").lower() == "true",
        "max_allocation": float(os.environ.get("FIREWALL_MAX_ALLOCATION", "0.25")),
    }

    result = verify_output(proposed_output, context=context)

    recommended_next_action = str(result.report.get("cost_aware_routing_recommendation", "verify_then_execute"))
    expected_total_cost_usd = float(
        (result.cost_estimate or {}).get(
            "expected_total_cost_usd",
            (result.cost_estimate or {}).get("total_expected_cost_usd", 0.0),
        )
    )

    print(
        json.dumps(
            {
                "decision": result.decision,
                "retry_tax_usd": result.retry_tax_usd,
                "expected_total_cost_usd": expected_total_cost_usd,
                "recommended_next_action": recommended_next_action,
            },
            sort_keys=True,
        )
    )

    sink = InMemoryFinalOutputSink(emitted=[])
    firewall = Firewall(sink=sink, strict_mode=False)

    try:
        firewall.submit_response(proposed_output, context=context)
    except (ConstraintViolationError, QuarantineRequiredError, PreconditionRequiredError) as exc:
        print(f"FIREWALL_EXCEPTION={exc.__class__.__name__}")
        return 1

    if result.decision in BLOCKING_DECISIONS:
        print(f"FIREWALL_BLOCK_DECISION={result.decision}")
        return 1

    allow_secrets = "true" if result.decision in SECRET_SAFE_DECISIONS else "false"
    _emit_output("allow_secrets", allow_secrets)
    _emit_output("decision", result.decision)
    _emit_output("retry_tax_usd", str(result.retry_tax_usd))
    _emit_output("expected_total_cost_usd", str(expected_total_cost_usd))
    _emit_output("recommended_next_action", recommended_next_action)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
