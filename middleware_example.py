from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gate import KeyRing, _GlassWingCore, configure_authority, register_tool
from interceptor import intercept_and_execute
from mcp_executor import PaymentGate


def _ctx(agent_id: str, policy_ids: list[str], token: str | None) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "agent_id": agent_id,
        "tenant_id": "tenant-demo",
        "session_id": "sess-demo",
        "tool_id": "tool.scan",
        "model_id": "model-demo",
        "runtime_id": "runtime-demo",
        "delegated_scope": "tool:scan",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "nonce": "nonce-demo",
        "jti": "jti-demo",
        "retry_count": 0,
        "policy_ids": policy_ids,
        "governance_token": token,
    }


def main() -> int:
    secret = "stage3-demo-secret"
    key_id = "kid-v1"
    agent_id = "agent-demo"
    intent = "safe_scan"
    tool_name = "tool.scan"
    policy_ids = ["policy.constitution.v1", "policy.solvency.v1"]

    configure_authority(
        key_ring=KeyRing(active_key_id=key_id, keys={key_id: secret}),
        payment_gate=PaymentGate(wallet_balances={agent_id: 50.0}),
    )

    def scan_tool(args: dict) -> dict:
        return {"ok": True, "echo": args.get("claim", "")}

    register_tool(tool_name, scan_tool)

    payload = {"claim": "safe claim"}
    base_ctx = _ctx(agent_id, policy_ids, None)

    outcome = intercept_and_execute(
        {"intent": intent, "intent_text": "safe claim", "tool_name": tool_name, "tool_args": payload, "domain": "finance"},
        base_ctx,
    )
    print("INTERCEPT_OUTCOME:", outcome)

    configure_authority(
        key_ring=KeyRing(active_key_id=key_id, keys={key_id: secret}),
        payment_gate=PaymentGate(wallet_balances={agent_id: 1.0}),
    )
    register_tool(tool_name, scan_tool)
    poor_outcome = intercept_and_execute(
        {"intent": intent, "intent_text": "safe claim", "tool_name": tool_name, "tool_args": payload, "domain": "finance"},
        base_ctx,
    )
    print("LOW_BALANCE_INTERCEPT_OUTCOME:", poor_outcome)

    try:
        _GlassWingCore().run("unsafe")
    except RuntimeError as exc:
        print("DIRECT_BYPASS_BLOCKED:", str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
