import unittest
from unittest.mock import patch

from gate import KeyRing, PaymentGate, configure_authority, execute, register_tool
from governance_service import execute as governance_execute
import interceptor as interceptor_module
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

    def test_interceptor_allowed_path_executes_registered_tool_once(self):
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

    def test_direct_gate_execute_returns_block(self):
        direct = execute("query_customer_data", self._ctx(), {"decision": "ALLOW"}, "tool.scan", {"claim": "safe"})
        self.assertEqual(direct["decision"], "BLOCK")
        self.assertEqual(direct["reason"], "intercept_and_execute required")

    def test_governance_service_execute_does_not_bypass_interceptor(self):
        blocked = governance_execute("query_customer_data", self._ctx(), {"decision": "ALLOW"}, "tool.scan", {"claim": "safe"})
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertEqual(blocked["reason"], "intercept_and_execute required")

    def test_domain_mismatch_blocks_before_token_issuance(self):
        ctx = self._ctx()
        ctx["allow_secrets"] = True
        with patch("interceptor.evaluate_request") as evaluate_mock, patch("interceptor.issue_governance_token") as issue_mock:
            out = intercept_and_execute(
                {
                    "intent": "query_customer_data",
                    "intent_text": "gravitational model for portfolio",
                    "tool_name": "tool.scan",
                    "tool_args": {"claim": "safe"},
                    "domain": "finance",
                },
                ctx,
            )
        self.assertEqual(out["decision"], "BLOCK")
        self.assertEqual(out["reason"], "DOMAIN_MISMATCH")
        evaluate_mock.assert_not_called()
        issue_mock.assert_not_called()
        self.assertNotIn("governance_issuance_ticket", ctx)

    def test_interceptor_does_not_call_public_blocked_execute(self):
        ctx = self._ctx()
        ctx["allow_secrets"] = True
        with patch("interceptor.execute_authorized_from_interceptor", wraps=interceptor_module.execute_authorized_from_interceptor) as internal_exec_mock:
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
        self.assertEqual(internal_exec_mock.call_count, 1)

    def test_execution_requires_interceptor(self):
        payload = {"claim": "safe"}
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

    def test_speculative_allocation_above_cap_blocks_before_token_issuance(self):
        ctx = self._ctx()
        ctx["allow_secrets"] = True
        with patch("interceptor.issue_governance_token") as issue_mock:
            out = intercept_and_execute(
                {
                    "intent": "invest",
                    "intent_text": "thesis",
                    "tool_name": "tool.scan",
                    "tool_args": {"claim": "thesis", "requested_allocation_pct": 3.0},
                    "domain": "finance",
                    "assumptions": [
                        {"assumption": "a", "status": "OBSERVABLE", "confidence": 0.7, "evidence": ["signal"], "falsification_trigger": "x", "critical": True},
                        {"assumption": "b", "status": "SPECULATIVE", "confidence": 0.6, "evidence": ["signal"], "falsification_trigger": "y", "critical": False},
                    ],
                    "confidence_average": 0.65,
                },
                ctx,
            )
        self.assertEqual(out["decision"], "BLOCK")
        self.assertEqual(out["reason"], "SPECULATIVE_ALLOCATION_EXCEEDS_CAP")
        issue_mock.assert_not_called()

    def test_speculative_allocation_within_cap_executes_through_interceptor(self):
        ctx = self._ctx()
        ctx["allow_secrets"] = True
        with patch("interceptor.execute_authorized_from_interceptor", wraps=interceptor_module.execute_authorized_from_interceptor) as internal_exec_mock:
            out = intercept_and_execute(
                {
                    "intent": "invest",
                    "intent_text": "thesis",
                    "tool_name": "tool.scan",
                    "tool_args": {"claim": "thesis", "requested_allocation_pct": 1.5},
                    "domain": "finance",
                    "assumptions": [
                        {"assumption": "a", "status": "OBSERVABLE", "confidence": 0.7, "evidence": ["signal"], "falsification_trigger": "x", "critical": True},
                        {"assumption": "b", "status": "SPECULATIVE", "confidence": 0.6, "evidence": ["signal"], "falsification_trigger": "y", "critical": False},
                    ],
                    "confidence_average": 0.65,
                },
                ctx,
            )
        self.assertEqual(out["decision"], "SPECULATE")
        self.assertTrue(out["speculative"])
        self.assertTrue(out["executed"])
        self.assertEqual(internal_exec_mock.call_count, 1)

    def test_simulation_allocation_above_cap_blocks_before_token_issuance(self):
        ctx = self._ctx()
        ctx["allow_secrets"] = True
        with patch("interceptor.issue_governance_token") as issue_mock:
            out = intercept_and_execute(
                {
                    "intent": "invest",
                    "intent_text": "thesis",
                    "tool_name": "tool.scan",
                    "tool_args": {"claim": "thesis", "requested_allocation_pct": 3.0},
                    "domain": "energy",
                    "run_simulation": True,
                    "simulation_count": 300,
                    "assumptions": [
                        {"assumption": "a", "status": "OBSERVABLE", "confidence": 0.75, "evidence": ["signal"], "falsification_trigger": "x", "critical": True, "low": 0.6, "base": 0.72, "high": 0.9, "weight": 1.0},
                    ],
                    "confidence_average": 0.75,
                },
                ctx,
            )
        self.assertEqual(out["decision"], "BLOCK")
        self.assertEqual(out["reason"], "SIMULATION_ALLOCATION_EXCEEDS_CAP")
        self.assertIn("simulation", out)
        issue_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
