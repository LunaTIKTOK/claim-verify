import unittest

from gate import KeyRing, PaymentGate, configure_authority, execute, issue_governance_token, mint_issuance_ticket, register_tool
from interceptor import intercept_and_execute


class InterceptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "int-secret"
        self.key_id = "int-kid"
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={"agent-int": 100.0}),
        )
        self.calls = {"n": 0}

        def tool(args: dict):
            self.calls["n"] += 1
            return {"ok": True, "args": args}

        register_tool("tool.scan", tool)
        register_tool("tool.secret.fetch", tool)

    def _ctx(self) -> dict:
        return {
            "agent_id": "agent-int",
            "tenant_id": "tenant-int",
            "session_id": "sess-int",
            "tool_id": "tool.scan",
            "model_id": "model-int",
            "runtime_id": "runtime-int",
            "delegated_scope": "tool:scan",
            "nonce": "nonce-int",
            "jti": "jti-int",
            "policy_ids": ["policy.constitution.v1"],
            "approval_token": "approved",
            "current_state": "RESEARCH",
            "requested_next_state": "READ_ONLY",
            "allow_secrets": False,
        }

    def test_domain_mismatch_blocks(self):
        out = intercept_and_execute(
            {
                "intent": "query_customer_data",
                "intent_text": "portfolio yield with gravitational model",
                "tool_name": "tool.scan",
                "tool_args": {"claim": "safe"},
                "domain": "finance",
            },
            self._ctx(),
        )
        self.assertEqual(out["decision"], "BLOCK")
        self.assertEqual(out["epistemic_status"], "UNSTABLE")
        self.assertEqual(out["reason"], "DOMAIN_MISMATCH")
        self.assertEqual(out["violations"], ["gravity"])
        self.assertFalse(out["executed"])

    def test_secret_tool_blocked_when_not_allowed(self):
        out = intercept_and_execute(
            {
                "intent": "query_customer_data",
                "intent_text": "safe claim",
                "tool_name": "tool.secret.fetch",
                "tool_args": {"claim": "safe"},
                "domain": "physics",
            },
            self._ctx(),
        )
        self.assertEqual(out["decision"], "BLOCK")
        self.assertFalse(out["executed"])

    def test_allow_path_executes(self):
        ctx = self._ctx()
        ctx["allow_secrets"] = True
        out = intercept_and_execute(
            {
                "intent": "query_customer_data",
                "intent_text": "safe claim",
                "tool_name": "tool.scan",
                "tool_args": {"claim": "safe"},
                "domain": "finance",
            },
            ctx,
        )
        self.assertEqual(out["decision"], "ALLOW")
        self.assertTrue(out["executed"])
        self.assertEqual(self.calls["n"], 1)

    def test_execution_requires_interceptor(self):
        payload = {"claim": "safe"}
        ctx = self._ctx()
        ctx["allow_secrets"] = True
        ctx["governance_issuance_ticket"] = mint_issuance_ticket("query_customer_data", ctx, "tool.scan", payload)
        issuance = issue_governance_token("query_customer_data", ctx, "tool.scan", payload)
        direct = execute("query_customer_data", ctx, issuance, "tool.scan", payload)
        self.assertEqual(direct["decision"], "BLOCK")
        self.assertEqual(direct["reason"], "intercept_and_execute required")

        out = intercept_and_execute(
            {
                "intent": "query_customer_data",
                "intent_text": "safe claim",
                "tool_name": "tool.scan",
                "tool_args": payload,
                "domain": "finance",
            },
            self._ctx(),
        )
        self.assertEqual(out["decision"], "ALLOW")
        self.assertTrue(out["executed"])


if __name__ == "__main__":
    unittest.main()
