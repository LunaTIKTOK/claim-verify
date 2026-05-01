from __future__ import annotations

import json

from gate import KeyRing, PaymentGate, configure_authority, register_tool
from interceptor import intercept_and_execute


def main() -> int:
    configure_authority(
        key_ring=KeyRing(active_key_id="demo-kid", keys={"demo-kid": "demo-secret"}),
        payment_gate=PaymentGate(wallet_balances={"demo-agent": 100.0}),
    )
    register_tool("tool.scan", lambda args: {"ok": True, "args": args})
    intent = {
        "intent": "invest_power",
        "intent_text": "AI power demand will create pricing power for firm power providers.",
        "claim": "AI power demand will create pricing power for firm power providers.",
        "tool_name": "tool.scan",
        "tool_args": {"claim": "thesis", "requested_allocation_pct": 1.5},
        "domain": "energy",
        "assumptions": [
            {"assumption": "AI compute demand continues growing faster than grid capacity.", "status": "OBSERVABLE", "confidence": 0.68, "evidence": ["demand growth signal"], "falsification_trigger": "AI load growth decelerates below grid expansion", "critical": True},
            {"assumption": "Hyperscalers continue signing long-term power agreements.", "status": "OBSERVABLE", "confidence": 0.66, "evidence": ["long-term contract signal"], "falsification_trigger": "PPA term lengths contract materially", "critical": True},
            {"assumption": "Nuclear/SMR deployment timelines remain uncertain.", "status": "SPECULATIVE", "confidence": 0.58, "evidence": ["delivery timing uncertainty"], "falsification_trigger": "SMR deployment accelerates ahead of baseline", "critical": False},
        ],
        "confidence_average": 0.64,
    }
    actor_context = {
        "state": "TRANSACTION",
        "agent_id": "demo-agent",
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
    print("=== Speculative Mode Demo Result ===")
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
