import unittest

from gate import KeyRing, PaymentGate, configure_authority, register_tool
from governance_service import evaluate_request, execute, issue_governance_token
from mcp_executor import SecurityViolationError
from runtime_governance import Constraint, RuntimeState, evaluate_runtime_governance


class RuntimeGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "rg-secret"
        self.key_id = "rg-kid"
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={"agent-runtime": 100.0}),
        )
        self.calls = {"n": 0}

        def tool(args: dict):
            self.calls["n"] += 1
            return {"ok": True, "args": args}

        register_tool("tool.scan", tool)

    def _actor_context(self) -> dict:
        return {
            "agent_id": "agent-runtime",
            "tenant_id": "tenant-runtime",
            "session_id": "sess-runtime",
            "tool_id": "tool.scan",
            "model_id": "model-runtime",
            "runtime_id": "runtime-runtime",
            "delegated_scope": "tool:scan",
            "nonce": "nonce-runtime",
            "jti": "jti-runtime",
            "policy_ids": ["policy.constitution.v1", "policy.solvency.v1"],
            "approval_token": "approved",
            "solvency_ok": True,
            "reputation_tier": "TRUSTED",
        }

    def test_state_based_denial(self):
        d = evaluate_runtime_governance(
            current_state=RuntimeState.QUARANTINED,
            requested_next_state=RuntimeState.READ_ONLY,
            tool_name="tool.scan",
            intent_class="SYSTEM_MODIFICATION",
            actor_identity_ok=True,
            approval_token_present=True,
            solvency_ok=True,
            reputation_tier="TRUSTED",
            policy_pack_paths=["packs/system_pack.json"],
        )
        self.assertEqual(d.status, "DENY")
        self.assertTrue(d.human_review_required)

    def test_state_transition_approval(self):
        d = evaluate_runtime_governance(
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.DRAFTING,
            tool_name="tool.scan",
            intent_class="DATA_ACCESS",
            actor_identity_ok=True,
            approval_token_present=False,
            solvency_ok=True,
            reputation_tier="TRUSTED",
            policy_pack_paths=["packs/system_pack.json"],
        )
        self.assertEqual(d.status, "ALLOW")

    def test_correction_requirement_generation(self):
        d = evaluate_runtime_governance(
            current_state=RuntimeState.TRANSACTION,
            requested_next_state=RuntimeState.TRANSACTION,
            tool_name="tool.pay",
            intent_class="PAYMENT",
            actor_identity_ok=True,
            approval_token_present=False,
            solvency_ok=True,
            reputation_tier="TRUSTED",
            policy_pack_paths=["packs/financial_pack.json"],
        )
        self.assertEqual(d.status, "DENY")
        self.assertIsNotNone(d.correction_requirement)
        self.assertEqual(d.correction_requirement.required_action, "FETCH_APPROVAL_TOKEN")
        self.assertEqual(d.correction_requirement.violation_type, "FETCH_APPROVAL_TOKEN")

    def test_hard_vs_soft_vs_goal_constraint_behavior(self):
        hard = Constraint(
            policy_id="HARD-1",
            level="HARD",
            denied_tools={"tool.blocked"},
            applies_to_states={RuntimeState.READ_ONLY},
        )
        soft = Constraint(
            policy_id="SOFT-1",
            level="SOFT",
            denied_transitions={(RuntimeState.DRAFTING, RuntimeState.READ_ONLY)},
        )
        goal = Constraint(
            policy_id="GOAL-1",
            level="GOAL",
            denied_tools={"tool.goal"},
        )

        d1 = evaluate_runtime_governance(
            current_state=RuntimeState.READ_ONLY,
            requested_next_state=RuntimeState.READ_ONLY,
            tool_name="tool.blocked",
            intent_class="DATA_ACCESS",
            actor_identity_ok=True,
            approval_token_present=True,
            solvency_ok=True,
            reputation_tier="TRUSTED",
            constraints=[hard],
        )
        self.assertEqual(d1.status, "DENY")

        d2 = evaluate_runtime_governance(
            current_state=RuntimeState.DRAFTING,
            requested_next_state=RuntimeState.READ_ONLY,
            tool_name="tool.ok",
            intent_class="DATA_ACCESS",
            actor_identity_ok=True,
            approval_token_present=True,
            solvency_ok=True,
            reputation_tier="TRUSTED",
            constraints=[soft],
            soft_override_justification="approved by supervisor",
        )
        self.assertEqual(d2.status, "ALLOW_WITH_JUSTIFICATION")

        d3 = evaluate_runtime_governance(
            current_state=RuntimeState.DRAFTING,
            requested_next_state=RuntimeState.READ_ONLY,
            tool_name="tool.goal",
            intent_class="DATA_ACCESS",
            actor_identity_ok=True,
            approval_token_present=True,
            solvency_ok=True,
            reputation_tier="TRUSTED",
            constraints=[goal],
        )
        self.assertEqual(d3.status, "ALLOW")

    def test_financial_pack_enforcement(self):
        d = evaluate_runtime_governance(
            current_state=RuntimeState.TRANSACTION,
            requested_next_state=RuntimeState.PRIVILEGED,
            tool_name="tool.trade",
            intent_class="TRADE",
            actor_identity_ok=True,
            approval_token_present=False,
            solvency_ok=False,
            reputation_tier="TRUSTED",
            policy_pack_paths=["packs/financial_pack.json"],
        )
        self.assertEqual(d.status, "DENY")
        self.assertGreaterEqual(len(d.violated_policies), 1)

    def test_privacy_pack_enforcement(self):
        d = evaluate_runtime_governance(
            current_state=RuntimeState.READ_ONLY,
            requested_next_state=RuntimeState.READ_ONLY,
            tool_name="tool.export",
            intent_class="DATA_EXPORT",
            actor_identity_ok=True,
            approval_token_present=True,
            solvency_ok=True,
            reputation_tier="TRUSTED",
            context={"contains_pii": True},
            policy_pack_paths=["packs/privacy_pack.json"],
        )
        self.assertEqual(d.status, "DENY")
        self.assertEqual(d.correction_requirement.required_action, "REDACT_PII")

    def test_allowed_flow_executes_once(self):
        actor_context = self._actor_context()
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}

        decision = evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        self.assertEqual(decision.status, "ALLOW")

        token = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        actor_context["governance_token"] = token

        result = execute("query_customer_data", actor_context, "tool.scan", tool_args)
        self.assertTrue(result["executed"])
        self.assertEqual(self.calls["n"], 1)

    def test_denied_cannot_issue_token_or_execute(self):
        actor_context = self._actor_context()
        actor_context["approval_token"] = ""
        actor_context["current_state"] = RuntimeState.TRANSACTION.value
        actor_context["requested_next_state"] = RuntimeState.PRIVILEGED.value
        tool_args = {"claim": "unsafe payment transfer"}

        decision = evaluate_request(
            intent="payment_transfer",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.TRANSACTION,
            requested_next_state=RuntimeState.PRIVILEGED,
        )
        self.assertEqual(decision.status, "DENY")
        with self.assertRaises(RuntimeError):
            issue_governance_token("payment_transfer", actor_context, "tool.scan", tool_args)

        with self.assertRaises(SecurityViolationError):
            execute("payment_transfer", actor_context, "tool.scan", tool_args)
        self.assertEqual(self.calls["n"], 0)

    def test_direct_issue_token_bypass(self):
        actor_context = self._actor_context()
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}

        with self.assertRaises(RuntimeError):
            issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)


if __name__ == "__main__":
    unittest.main()
