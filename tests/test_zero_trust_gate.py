import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from audit import ALLOWED_CODES, AuditLogger
from authority import build_token, serialize_token
from gate import blocked_core_access, blocked_tool_access, configure_authority, execute, register_tool
from mcp_executor import PaymentGate, SecurityViolationError


class Stage3GovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "stage3-secret"
        self.agent_id = "agent-a"
        self.intent = "safe_scan"
        self.tool_name = "tool.scan"
        self.policy_ids = ["policy.constitution.v1", "policy.solvency.v1"]
        self.payment_gate = PaymentGate(wallet_balances={self.agent_id: 100.0})
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_path = Path(self.tmp.name) / "audit.jsonl"
        configure_authority(
            secret=self.secret,
            payment_gate=self.payment_gate,
            audit_logger=AuditLogger(self.audit_path),
        )

        def scan_tool(args: dict):
            return {"ok": True, "echo": args.get("claim", "")}

        register_tool(self.tool_name, scan_tool)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _context(self, token: str | None) -> dict:
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
            "retry_count": 0,
            "policy_ids": self.policy_ids,
            "governance_token": token,
        }

    def _valid_token(self, *, tool_name: str | None = None, agent_id: str | None = None, ttl_seconds: int = 300) -> str:
        token = build_token(
            agent_id=agent_id or self.agent_id,
            intent=self.intent,
            tool_name=tool_name or self.tool_name,
            policy_ids=self.policy_ids,
            secret=self.secret,
            ttl_seconds=ttl_seconds,
        )
        return serialize_token(token)

    def test_valid_signed_token_execution(self):
        out = execute(
            self.intent,
            self._context(self._valid_token()),
            self.tool_name,
            {"claim": "System has measurable 99% uptime in 30 days."},
        )
        self.assertTrue(out["executed"])

    def test_missing_token_denial(self):
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(None), self.tool_name, {"claim": "safe"})

    def test_forged_token_denial(self):
        forged = self._valid_token()[:-2] + "00"
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(forged), self.tool_name, {"claim": "safe"})

    def test_expired_token_denial(self):
        expired = self._valid_token(ttl_seconds=-5)
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(expired), self.tool_name, {"claim": "safe"})

    def test_wrong_tool_token_denial(self):
        bad_tool_token = self._valid_token(tool_name="tool.other")
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(bad_tool_token), self.tool_name, {"claim": "safe"})

    def test_wrong_agent_token_denial(self):
        bad_agent_token = self._valid_token(agent_id="agent-b")
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(bad_agent_token), self.tool_name, {"claim": "safe"})

    def test_replay_attack_denial(self):
        token = self._valid_token()
        context = self._context(token)
        execute(self.intent, context, self.tool_name, {"claim": "safe"})
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, context, self.tool_name, {"claim": "safe"})

    def test_direct_core_access_failure(self):
        with self.assertRaises(RuntimeError):
            blocked_core_access().run("x")

    def test_direct_tool_access_failure(self):
        with self.assertRaises(RuntimeError):
            blocked_tool_access().invoke_tool(self.tool_name, {"claim": "x"})

    def test_allowed_codes_contains_security_violation(self):
        self.assertIn("SECURITY_VIOLATION", ALLOWED_CODES)


if __name__ == "__main__":
    unittest.main()
