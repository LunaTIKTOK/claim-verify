from __future__ import annotations

import json

from gate import KeyRing, PaymentGate, configure_authority, register_tool
from interceptor import intercept_and_execute


def main() -> int:
    configure_authority(
        key_ring=KeyRing(active_key_id="demo-kid", keys={"demo-kid": "demo-secret"}),
        payment_gate=PaymentGate(wallet_balances={"sim-agent": 100.0}),
    )
    register_tool("tool.scan", lambda args: {"ok": True, "args": args})
    intent = {
        "intent": "invest_power",
        "intent_text": "AI power demand will create pricing power for firm power providers.",
        "claim": "AI power demand will create pricing power for firm power providers.",
        "tool_name": "tool.scan",
        "tool_args": {"claim": "thesis", "requested_allocation_pct": 1.0},
        "requested_allocation_pct": 1.0,
        "domain": "energy",
        "run_simulation": True,
        "simulation_count": 1000,
        "assumptions": [
            {"assumption": "AI compute demand growth", "status": "OBSERVABLE", "confidence": 0.7, "evidence": ["signal"], "falsification_trigger": "demand trend breaks", "critical": True, "low": 0.45, "base": 0.7, "high": 0.9, "weight": 1.2},
            {"assumption": "grid expansion delay", "status": "OBSERVABLE", "confidence": 0.65, "evidence": ["signal"], "falsification_trigger": "grid catches up", "critical": True, "low": 0.35, "base": 0.65, "high": 0.85, "weight": 1.0},
            {"assumption": "hyperscaler long-term power contracting", "status": "OBSERVABLE", "confidence": 0.68, "evidence": ["signal"], "falsification_trigger": "contract tenors shrink", "critical": True, "low": 0.4, "base": 0.68, "high": 0.88, "weight": 1.0},
            {"assumption": "regulatory delay", "status": "SPECULATIVE", "confidence": 0.58, "evidence": ["signal"], "falsification_trigger": "regulatory acceleration", "critical": False, "low": 0.3, "base": 0.58, "high": 0.8, "weight": 0.8},
            {"assumption": "cost of capital", "status": "SPECULATIVE", "confidence": 0.6, "evidence": ["signal"], "falsification_trigger": "capital costs spike", "critical": False, "low": 0.35, "base": 0.6, "high": 0.8, "weight": 0.7},
        ],
        "confidence_average": 0.64,
    }
    actor_context = {
        "agent_id": "sim-agent",
        "tenant_id": "tenant-demo",
        "session_id": "sess-demo",
        "tool_id": "tool.scan",
        "model_id": "model-demo",
        "runtime_id": "runtime-demo",
        "delegated_scope": "tool:scan",
        "nonce": "nonce-demo",
        "jti": "jti-demo",
        "policy_ids": ["policy.constitution.v1"],
        "approval_token": "approved",
        "current_state": "RESEARCH",
        "requested_next_state": "READ_ONLY",
        "allow_secrets": False,
    }
    out = intercept_and_execute(intent, actor_context)
    print("=== Simulation Speculation Demo Result ===")
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
