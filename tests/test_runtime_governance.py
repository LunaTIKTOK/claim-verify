import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from audit import AuditLogger
from benchmark_firewall_economics import ScenarioConfig, run_firewall_scenario
from gate import (
    KeyRing,
    PaymentGate,
    SQLiteGovernanceStateStore,
    configure_authority,
    execute_authorized_from_interceptor,
    issue_governance_token as gate_issue_governance_token,
    mint_issuance_ticket,
    register_tool,
)
from governance_service import evaluate_request, issue_governance_token
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
        register_tool("tool.secret.fetch", tool)

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

        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        self.assertEqual(issuance["decision"], "ALLOW")
        self.assertIsNotNone(issuance["token"])
        result = execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.scan", tool_args)
        self.assertTrue(result["executed"])
        self.assertEqual(self.calls["n"], 1)

    def test_denied_cannot_issue_token_or_execute_authorized_from_interceptor(self):
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
        issuance = issue_governance_token("payment_transfer", actor_context, "tool.scan", tool_args)
        self.assertEqual(issuance["decision"], "BLOCK")
        self.assertIsNone(issuance["token"])

        blocked = execute_authorized_from_interceptor("payment_transfer", actor_context, issuance, "tool.scan", tool_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertFalse(blocked["executed"])
        self.assertEqual(self.calls["n"], 0)

    def test_direct_issue_token_bypass(self):
        actor_context = self._actor_context()
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}

        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        self.assertEqual(issuance["decision"], "BLOCK")
        self.assertIsNone(issuance["token"])

    def test_invalid_state_transition_blocks(self):
        actor_context = self._actor_context()
        actor_context["state"] = "RESEARCH"
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}

        actor_context["governance_issuance_ticket"] = mint_issuance_ticket(
            "payment_transfer", actor_context, "tool.scan", tool_args
        )

        issuance = gate_issue_governance_token("payment_transfer", actor_context, "tool.scan", tool_args)
        self.assertEqual(issuance["decision"], "BLOCK")
        self.assertEqual(issuance["next_state"], "RESEARCH")

    def test_allow_secrets_false_blocks_secret_tool(self):
        actor_context = self._actor_context()
        actor_context["state"] = "RESEARCH"
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        actor_context["allow_secrets"] = True
        tool_args = {"claim": "safe claim"}

        actor_context["governance_issuance_ticket"] = mint_issuance_ticket(
            "query_customer_data", actor_context, "tool.secret.fetch", tool_args
        )
        issuance = gate_issue_governance_token("query_customer_data", actor_context, "tool.secret.fetch", tool_args)
        self.assertEqual(issuance["decision"], "ALLOW")
        actor_context["allow_secrets"] = False
        issuance["allow_secrets"] = False

        out = execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.secret.fetch", tool_args)
        self.assertEqual(out["decision"], "BLOCK")
        self.assertFalse(out["executed"])

    def test_next_state_updates_on_decision(self):
        actor_context = self._actor_context()
        actor_context["state"] = "RESEARCH"
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}
        evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        self.assertEqual(issuance["next_state"], "READ_ONLY")

    def test_retry_count_increments_in_benchmark(self):
        result = run_firewall_scenario(ScenarioConfig(name="retry_test", mode="ambiguous", attempts=2))
        self.assertEqual(result["retry_count"], 1)
        self.assertIn("retry_tax_usd", result)
        self.assertIn("terminal", result)

    def test_token_replay_with_different_tool_blocks(self):
        actor_context = self._actor_context()
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}
        evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        blocked = execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.secret.fetch", tool_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertFalse(blocked["executed"])

    def test_payload_tampering_blocks(self):
        actor_context = self._actor_context()
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}
        tampered_args = {"claim": "tampered claim"}
        evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        blocked = execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.scan", tampered_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertFalse(blocked["executed"])

    def test_manual_state_escalation_blocks(self):
        actor_context = self._actor_context()
        actor_context["state"] = "PRIVILEGED"
        actor_context["current_state"] = RuntimeState.RESEARCH.value
        actor_context["requested_next_state"] = RuntimeState.READ_ONLY.value
        tool_args = {"claim": "safe claim"}
        actor_context["governance_issuance_ticket"] = mint_issuance_ticket(
            "payment_transfer", actor_context, "tool.scan", tool_args
        )
        issuance = gate_issue_governance_token("payment_transfer", actor_context, "tool.scan", tool_args)
        self.assertEqual(issuance["decision"], "BLOCK")
        self.assertIn("invalid transition", issuance["reason"])

    def test_execution_without_governance_decision_blocks(self):
        actor_context = self._actor_context()
        blocked = execute_authorized_from_interceptor("query_customer_data", actor_context, None, "tool.scan", {"claim": "safe"})
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertFalse(blocked["executed"])

    def test_invalid_actor_identity_returns_block(self):
        actor_context = self._actor_context()
        tool_args = {"claim": "safe claim"}
        evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        bad_context = dict(actor_context)
        bad_context.pop("agent_id", None)
        blocked = execute_authorized_from_interceptor("query_customer_data", bad_context, issuance, "tool.scan", tool_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertEqual(blocked["reason"], "invalid actor identity")

    def test_policy_denied_execution_returns_block(self):
        actor_context = self._actor_context()
        tool_args = {"claim": "unsafe unsupported high risk claim with no evidence"}
        evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        with patch("gate.decide_policy", return_value="DENY"):
            blocked = execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.scan", tool_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertEqual(blocked["reason"], "policy denied execution")

    def test_insufficient_solvency_returns_block(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={"agent-runtime": 1.0}),
        )
        register_tool("tool.scan", lambda args: {"ok": True, "args": args})
        actor_context = self._actor_context()
        tool_args = {"claim": "safe claim"}
        evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        blocked = execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.scan", tool_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertEqual(blocked["reason"], "insufficient solvency for governance bond")

    def test_failed_bond_lock_returns_block(self):
        class RefusingLockGate(PaymentGate):
            def lock_bond(self, agent_id: str, amount_usd: float) -> bool:  # type: ignore[override]
                return False

        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=RefusingLockGate(wallet_balances={"agent-runtime": 100.0}),
        )
        register_tool("tool.scan", lambda args: {"ok": True, "args": args})
        actor_context = self._actor_context()
        tool_args = {"claim": "safe claim"}
        evaluate_request(
            intent="query_customer_data",
            tool_name="tool.scan",
            actor_context=actor_context,
            tool_args=tool_args,
            current_state=RuntimeState.RESEARCH,
            requested_next_state=RuntimeState.READ_ONLY,
        )
        issuance = issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        blocked = execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.scan", tool_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertEqual(blocked["reason"], "failed to lock governance bond")

    def test_state_continuity_survives_restart_with_sqlite_store(self):
        tmp = tempfile.TemporaryDirectory()
        db = str(Path(tmp.name) / "gov_state.db")
        store = SQLiteGovernanceStateStore(db)
        actor_context = self._actor_context()
        tool_args = {"claim": "safe claim"}

        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={"agent-runtime": 100.0}),
            governance_state_store=store,
        )
        register_tool("tool.scan", lambda args: {"ok": True, "args": args})
        actor_context["governance_issuance_ticket"] = mint_issuance_ticket("query_customer_data", actor_context, "tool.scan", tool_args)
        issuance = gate_issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.scan", tool_args)

        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={"agent-runtime": 100.0}),
            governance_state_store=SQLiteGovernanceStateStore(db),
        )
        register_tool("tool.scan", lambda args: {"ok": True, "args": args})
        actor_context["governance_issuance_ticket"] = mint_issuance_ticket("payment_transfer", actor_context, "tool.scan", tool_args)
        blocked = gate_issue_governance_token("payment_transfer", actor_context, "tool.scan", tool_args)
        self.assertEqual(blocked["decision"], "BLOCK")
        tmp.cleanup()

    def test_correlation_id_propagates_in_audit(self):
        tmp = tempfile.TemporaryDirectory()
        audit_path = Path(tmp.name) / "audit.jsonl"
        actor_context = self._actor_context()
        actor_context["correlation_id"] = "cid-runtime-1"
        tool_args = {"claim": "safe claim"}
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={"agent-runtime": 100.0}),
            audit_logger=AuditLogger(audit_path),
        )
        register_tool("tool.scan", lambda args: {"ok": True, "args": args})
        actor_context["governance_issuance_ticket"] = mint_issuance_ticket("query_customer_data", actor_context, "tool.scan", tool_args)
        issuance = gate_issue_governance_token("query_customer_data", actor_context, "tool.scan", tool_args)
        execute_authorized_from_interceptor("query_customer_data", actor_context, issuance, "tool.scan", tool_args)

        rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(any(row.get("correlation_id") == "cid-runtime-1" for row in rows))
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
