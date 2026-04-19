from __future__ import annotations

from datetime import datetime, timedelta, timezone

from authority import build_token, serialize_token
from gate import blocked_core_access, configure_authority, execute, register_tool
from mcp_executor import PaymentGate, SecurityViolationError


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


def _build_token(secret: str, agent_id: str, intent: str, tool_name: str, policy_ids: list[str]) -> str:
    return serialize_token(
        build_token(
            agent_id=agent_id,
            intent=intent,
            tool_name=tool_name,
            policy_ids=policy_ids,
            secret=secret,
            ttl_seconds=300,
        )
    )


def main() -> int:
    secret = "stage3-demo-secret"
    agent_id = "agent-demo"
    intent = "safe_scan"
    tool_name = "tool.scan"
    policy_ids = ["policy.constitution.v1", "policy.solvency.v1"]

    configure_authority(secret=secret, payment_gate=PaymentGate(wallet_balances={agent_id: 50.0}))

    def scan_tool(args: dict) -> dict:
        return {"ok": True, "echo": args.get("claim", "")}

    register_tool(tool_name, scan_tool)

    good_token = _build_token(secret, agent_id, intent, tool_name, policy_ids)
    out = execute(intent, _ctx(agent_id, policy_ids, good_token), tool_name, {"claim": "safe claim"})
    print("AUTHORIZED_EXECUTION:", out["executed"], out["result"])

    forged = good_token[:-1] + ("0" if good_token[-1] != "0" else "1")
    try:
        execute(intent, _ctx(agent_id, policy_ids, forged), tool_name, {"claim": "safe claim"})
    except SecurityViolationError as exc:
        print("FORGED_TOKEN_BLOCKED:", exc.reason, exc.retry_tax_usd, exc.bond_forfeited_usd)

    replay = _build_token(secret, agent_id, intent, tool_name, policy_ids)
    execute(intent, _ctx(agent_id, policy_ids, replay), tool_name, {"claim": "safe claim"})
    try:
        execute(intent, _ctx(agent_id, policy_ids, replay), tool_name, {"claim": "safe claim"})
    except SecurityViolationError as exc:
        print("REPLAY_BLOCKED:", exc.reason, exc.retry_tax_usd, exc.bond_forfeited_usd)

    configure_authority(secret=secret, payment_gate=PaymentGate(wallet_balances={agent_id: 1.0}))
    register_tool(tool_name, scan_tool)
    poor_token = _build_token(secret, agent_id, intent, tool_name, policy_ids)
    try:
        execute(intent, _ctx(agent_id, policy_ids, poor_token), tool_name, {"claim": "safe claim"})
    except RuntimeError as exc:
        print("INSUFFICIENT_BALANCE_LOCKOUT:", str(exc))

    try:
        blocked_core_access().run("unsafe")
    except RuntimeError as exc:
        print("DIRECT_BYPASS_BLOCKED:", str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
