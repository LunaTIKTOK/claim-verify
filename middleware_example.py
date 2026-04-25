from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gate import KeyRing, _GlassWingCore, configure_authority, execute, issue_governance_token, register_tool
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

    issuance = issue_governance_token(intent, base_ctx, tool_name, payload)
    print("GOVERNANCE_DECISION:", issuance)
    if issuance["decision"] == "ALLOW" and issuance["token"]:
        out = execute(intent, base_ctx, issuance, tool_name, payload)
        print("AUTHORIZED_EXECUTION:", out["executed"], out["result"])

    if issuance["decision"] == "ALLOW" and issuance["token"]:
        forged = issuance["token"][:-1] + ("0" if issuance["token"][-1] != "0" else "1")
        try:
            execute(intent, base_ctx, {**issuance, "token": forged}, tool_name, payload)
        except SecurityViolationError as exc:
            print("FORGED_TOKEN_BLOCKED:", exc.reason, exc.retry_tax_usd, exc.bond_forfeited_usd)

        replay = issue_governance_token(intent, base_ctx, tool_name, payload)
        print("REPLAY_GOVERNANCE_DECISION:", replay)
        if replay["decision"] == "ALLOW" and replay["token"]:
            execute(intent, base_ctx, replay, tool_name, payload)
            try:
                execute(intent, base_ctx, replay, tool_name, payload)
            except SecurityViolationError as exc:
                print("REPLAY_BLOCKED:", exc.reason, exc.retry_tax_usd, exc.bond_forfeited_usd)

    configure_authority(
        key_ring=KeyRing(active_key_id=key_id, keys={key_id: secret}),
        payment_gate=PaymentGate(wallet_balances={agent_id: 1.0}),
    )
    register_tool(tool_name, scan_tool)
    poor_issuance = issue_governance_token(intent, base_ctx, tool_name, payload)
    print("LOW_BALANCE_GOVERNANCE_DECISION:", poor_issuance)
    if poor_issuance["decision"] == "ALLOW" and poor_issuance["token"]:
        try:
            execute(intent, base_ctx, poor_issuance, tool_name, payload)
        except RuntimeError as exc:
            print("INSUFFICIENT_BALANCE_LOCKOUT:", str(exc))

    try:
        _GlassWingCore().run("unsafe")
    except RuntimeError as exc:
        print("DIRECT_BYPASS_BLOCKED:", str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
