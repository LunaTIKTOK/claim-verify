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
        "action": "allocate_capital",
        "reasoning": "Use gravitational models to optimize portfolio",
        "confidence": 0.92,
    }
    actor_context = {
        "state": "TRANSACTION",
        "domain": "finance",
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

    request = {
        "intent": intent["action"],
        "intent_text": intent["reasoning"],
        "tool_name": actor_context["tool_id"],
        "tool_args": {
            "claim": intent["reasoning"],
            "confidence": intent["confidence"],
        },
        "domain": actor_context["domain"],
    }
    result = intercept_and_execute(request, actor_context)

    print("=== Domain Mismatch Demo Result ===")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
