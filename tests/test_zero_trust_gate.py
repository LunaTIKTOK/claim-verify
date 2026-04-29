import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from audit import ALLOWED_CODES, AuditLogger
from authority import InMemoryUsedTokenStore, build_token, compute_payload_hash, serialize_token
from gate import KeyRing, _GlassWingCore, configure_authority, execute, issue_governance_token, mint_issuance_ticket, register_tool
from mcp_executor import PaymentGate, SecurityViolationError


class Stage3GovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "stage3-secret"
        self.key_id = "kid-v1"
        self.agent_id = "agent-a"
        self.intent = "safe_scan"
        self.tool_name = "tool.scan"
        self.policy_ids = ["policy.constitution.v1", "policy.solvency.v1"]
        self.payment_gate = PaymentGate(wallet_balances={self.agent_id: 100.0})
        self.token_store = InMemoryUsedTokenStore()
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_path = Path(self.tmp.name) / "audit.jsonl"
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=self.payment_gate,
            used_token_store=self.token_store,
            audit_logger=AuditLogger(self.audit_path),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "echo": args.get("claim", "")})

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

    def _issue_token(self, tool_name: str, payload: dict, ctx: dict | None = None) -> dict:
        context = dict(ctx or self._context(None))
        context["governance_issuance_ticket"] = mint_issuance_ticket(self.intent, context, tool_name, payload)
        issuance = issue_governance_token(self.intent, context, tool_name, payload)
        self.assertEqual(issuance["decision"], "ALLOW")
        self.assertIsNotNone(issuance["token"])
        return issuance

    def test_valid_signed_token_execution(self):
        payload = {"claim": "System has measurable 99% uptime in 30 days."}
        ctx = self._context(None)
        issuance = self._issue_token(self.tool_name, payload, ctx)
        out = execute(self.intent, ctx, issuance, self.tool_name, payload)
        self.assertTrue(out["executed"])

    def test_token_must_be_issued_before_execution(self):
        payload = {"claim": "safe"}
        raw_token = serialize_token(
            build_token(
                key_id=self.key_id,
                agent_id=self.agent_id,
                intent=self.intent,
                tool_name=self.tool_name,
                policy_ids=self.policy_ids,
                payload_hash=compute_payload_hash(payload),
                secret=self.secret,
            )
        )
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(raw_token), {"decision": "ALLOW", "allow_secrets": True, "token": raw_token, "reason": None, "next_state": "READ_ONLY"}, self.tool_name, payload)

    def test_payload_binding_denial(self):
        token_payload = {"claim": "safe"}
        tampered_payload = {"claim": "tampered"}
        issuance = self._issue_token(self.tool_name, token_payload)
        blocked = execute(self.intent, self._context(None), issuance, self.tool_name, tampered_payload)
        self.assertEqual(blocked["decision"], "BLOCK")

    def test_revoked_token_cannot_be_reused(self):
        def failing_tool(_args: dict):
            raise RuntimeError("tool failure")

        register_tool("tool.fail", failing_tool)
        payload = {"claim": "safe"}
        issuance = self._issue_token("tool.fail", payload)
        with self.assertRaises(RuntimeError):
            execute(self.intent, self._context(None), issuance, "tool.fail", payload)
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(None), issuance, "tool.fail", payload)

    def test_pending_token_cannot_be_reused_concurrently(self):
        payload = {"claim": "safe"}
        issuance = self._issue_token(self.tool_name, payload)
        from authority import deserialize_token

        token_obj = deserialize_token(str(issuance["token"]))
        self.assertTrue(self.token_store.mark_pending(token_obj.token_id))
        with self.assertRaises(SecurityViolationError):
            execute(self.intent, self._context(None), issuance, self.tool_name, payload)

    def test_direct_core_access_failure(self):
        with self.assertRaises(RuntimeError):
            _GlassWingCore().run("x")

    def test_allowed_codes_contains_security_violation(self):
        self.assertIn("SECURITY_VIOLATION", ALLOWED_CODES)


if __name__ == "__main__":
    unittest.main()
