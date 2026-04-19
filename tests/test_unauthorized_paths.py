import unittest
from datetime import datetime, timedelta, timezone

from authority import build_token, serialize_token
from gate import blocked_core_access, blocked_tool_access, configure_authority, execute, register_tool
from mcp_executor import PaymentGate, SecurityViolationError


class UnauthorizedPathAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "audit-secret"
        self.agent_id = "agent-a"
        self.intent = "safe_scan"
        self.tool_name = "tool.scan"
        self.policy_ids = ["policy.constitution.v1"]
        configure_authority(secret=self.secret, payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}))
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})

    def _ctx(self, token: str | None) -> dict:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        return {
            "agent_id": self.agent_id,
            "tenant_id": "tenant-1",
            "session_id": "sess-1",
            "tool_id": self.tool_name,
            "model_id": "model-z",
            "runtime_id": "runtime-z",
            "delegated_scope": "tool:scan",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "nonce": "nonce-1",
            "jti": "jti-1",
            "policy_ids": self.policy_ids,
            "governance_token": token,
        }

    def _token(self, *, agent_id: str | None = None, tool_name: str | None = None) -> str:
        token = build_token(
            agent_id=agent_id or self.agent_id,
            intent=self.intent,
            tool_name=tool_name or self.tool_name,
            policy_ids=self.policy_ids,
            secret=self.secret,
        )
        return serialize_token(token)

    def test_direct_core_access_fails(self):
        with self.assertRaises(RuntimeError):
            blocked_core_access().run("unsafe")

    def test_direct_tool_access_fails(self):
        with self.assertRaises(RuntimeError):
            blocked_tool_access().invoke_tool(self.tool_name, {"claim": "x"})

    def test_missing_token_fails(self):
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(None), self.tool_name, {"claim": "safe"})

    def test_replay_fails(self):
        token = self._token()
        ctx = self._ctx(token)
        execute(self.intent, ctx, self.tool_name, {"claim": "safe"})
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, ctx, self.tool_name, {"claim": "safe"})

    def test_wrong_tool_token_fails(self):
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(self._token(tool_name="tool.other")), self.tool_name, {"claim": "safe"})

    def test_wrong_agent_token_fails(self):
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._ctx(self._token(agent_id="agent-b")), self.tool_name, {"claim": "safe"})


if __name__ == "__main__":
    unittest.main()
