import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from authority import InMemoryUsedTokenStore, SQLiteUsedTokenStore, build_token, compute_payload_hash, serialize_token
from gate import KeyRing, _GlassWingCore, configure_authority, execute_authorized_from_interceptor, issue_governance_token, mint_issuance_ticket, register_tool
from mcp_executor import PaymentGate, SQLitePaymentGate, SecurityViolationError


class UnauthorizedPathAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "audit-secret"
        self.key_id = "kid-v1"
        self.agent_id = "agent-a"
        self.intent = "safe_scan"
        self.tool_name = "tool.scan"
        self.policy_ids = ["policy.constitution.v1"]

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

    def _issue_token(self, tool_name: str, payload: dict, ctx: dict | None = None) -> dict:
        context = dict(ctx or self._ctx(None))
        context["governance_issuance_ticket"] = mint_issuance_ticket(self.intent, context, tool_name, payload)
        issuance = issue_governance_token(self.intent, context, tool_name, payload)
        self.assertEqual(issuance["decision"], "ALLOW")
        self.assertIsNotNone(issuance["token"])
        return issuance

    def test_direct_core_access_fails(self):
        with self.assertRaises(RuntimeError):
            _GlassWingCore().run("unsafe")

    def test_executor_cannot_bootstrap_lifecycle(self):
        store = InMemoryUsedTokenStore()
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
            used_token_store=store,
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
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
            execute_authorized_from_interceptor(self.intent, self._ctx(raw_token), {"decision": "ALLOW", "allow_secrets": True, "token": raw_token, "reason": None, "next_state": "READ_ONLY"}, self.tool_name, payload)
        from authority import deserialize_token

        self.assertIsNone(store.get_status(deserialize_token(raw_token).token_id))

    def test_missing_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        blocked = execute_authorized_from_interceptor(self.intent, self._ctx(None), {"decision": "ALLOW", "allow_secrets": True, "token": None, "reason": None, "next_state": "READ_ONLY"}, self.tool_name, {"claim": "safe"})
        self.assertEqual(blocked["decision"], "BLOCK")

    def test_forged_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        payload = {"claim": "safe"}
        issuance = self._issue_token(self.tool_name, payload)
        token = str(issuance["token"])
        forged = token[:-1] + ("0" if token[-1] != "0" else "1")
        blocked = execute_authorized_from_interceptor(self.intent, self._ctx(None), {**issuance, "token": forged}, self.tool_name, payload)
        self.assertEqual(blocked["decision"], "BLOCK")

    def test_replay_fails_after_restart_with_sqlite_store(self):
        tmp = tempfile.TemporaryDirectory()
        db = str(Path(tmp.name) / "tokens.db")

        payload = {"claim": "safe"}
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
            used_token_store=SQLiteUsedTokenStore(db),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        issuance = self._issue_token(self.tool_name, payload)
        execute_authorized_from_interceptor(self.intent, self._ctx(None), issuance, self.tool_name, payload)

        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
            used_token_store=SQLiteUsedTokenStore(db),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        with self.assertRaises(SecurityViolationError):
            execute_authorized_from_interceptor(self.intent, self._ctx(None), issuance, self.tool_name, payload)
        tmp.cleanup()

    def test_wrong_tool_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        payload = {"claim": "safe"}
        issuance = self._issue_token("tool.other", payload)
        blocked = execute_authorized_from_interceptor(self.intent, self._ctx(None), issuance, self.tool_name, payload)
        self.assertEqual(blocked["decision"], "BLOCK")

    def test_wrong_agent_token_fails(self):
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0, "agent-b": 100.0}),
        )
        register_tool(self.tool_name, lambda args: {"ok": True, "args": args})
        payload = {"claim": "safe"}
        issuance = self._issue_token(self.tool_name, payload, {**self._ctx(None), "agent_id": "agent-b"})
        with self.assertRaises(SecurityViolationError):
            execute_authorized_from_interceptor(self.intent, self._ctx(None), issuance, self.tool_name, payload)

    def test_payment_gate_transactional_locking_under_concurrency(self):
        tmp = tempfile.TemporaryDirectory()
        db = str(Path(tmp.name) / "payments.db")
        gate = SQLitePaymentGate(db)
        gate.seed_balance("a", 10.0)

        results: list[bool] = []

        def worker() -> None:
            results.append(gate.lock_bond("a", 7.0))

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(sum(1 for r in results if r), 1)
        tmp.cleanup()

    def test_repo_wide_bypass_audit_no_tool_without_valid_governance(self):
        calls = {"n": 0}
        configure_authority(
            key_ring=KeyRing(active_key_id=self.key_id, keys={self.key_id: self.secret}),
            payment_gate=PaymentGate(wallet_balances={self.agent_id: 100.0}),
        )

        def counted_tool(_args: dict):
            calls["n"] += 1
            return {"ok": True}

        register_tool(self.tool_name, counted_tool)
        payload = {"claim": "safe", "api_key": "sekret"}

        # No governance decision.
        blocked = execute_authorized_from_interceptor(self.intent, self._ctx(None), None, self.tool_name, payload)
        self.assertEqual(blocked["decision"], "BLOCK")

        # Governance decision but no token.
        blocked = execute_authorized_from_interceptor(
            self.intent,
            self._ctx(None),
            {"decision": "ALLOW", "allow_secrets": True, "token": None, "reason": None, "next_state": "READ_ONLY"},
            self.tool_name,
            payload,
        )
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertEqual(calls["n"], 0)


if __name__ == "__main__":
    unittest.main()
